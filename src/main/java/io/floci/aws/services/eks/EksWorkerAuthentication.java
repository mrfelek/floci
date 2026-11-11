package io.floci.aws.services.eks;

import io.floci.aws.config.EmulatorConfig;
import io.floci.aws.core.common.AwsArnUtils;
import io.floci.aws.core.common.AwsException;
import io.floci.aws.services.ec2.Ec2Service;
import io.floci.aws.services.ec2.model.Instance;
import io.floci.aws.services.eks.model.Cluster;
import io.floci.aws.services.iam.IamService;
import io.floci.aws.services.iam.IamService.EksCaller;
import io.floci.aws.services.iam.IamService.EksSessionIdentity;
import io.floci.aws.services.iam.model.IamRole;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Maps a verified EKS token to its Kubernetes identity. Instance credentials become node identities, from
 * server-owned EC2 metadata and the role's EC2_LINUX access entry.
 *
 * <p>With IAM enforcement on, every other IAM user or role is authenticated as EKS authenticates it, by the
 * cluster's authentication mode:
 * <ul>
 *   <li>{@code API} and {@code API_AND_CONFIG_MAP}: the cluster's STANDARD access entry for the principal gives
 *       the entry's username, with {@code {{SessionName}}} filled in, and its Kubernetes groups;</li>
 *   <li>{@code CONFIG_MAP}: the cluster's creator, which EKS maps to {@code system:masters} without any visible
 *       configuration.</li>
 * </ul>
 * Floci does not read the deprecated {@code aws-auth} ConfigMap, which access entries replace, so a principal
 * only it maps is not authenticated. Neither is a principal nothing maps. The account root (a key that names no IAM user, such as
 * {@code test} or a bare account id) keeps the administrator identity in its own account, as IAM enforcement
 * also lets it through.
 *
 * <p>With enforcement off, callers keep the identities they get today.
 */
@ApplicationScoped
class EksWorkerAuthentication {
    /** The {@code extra} attribute naming the access entry's principal, read by the authorization webhook. */
    static final String PRINCIPAL_ARN_EXTRA = "eks.floci.io/principal-arn";
    /** The {@code extra} attribute signing {@link #PRINCIPAL_ARN_EXTRA}; see {@link EksAccessIdentitySigner}. */
    static final String SIGNATURE_EXTRA = "eks.floci.io/signature";

    private final IamService iam;
    private final EksService eks;
    private final Ec2Service ec2;
    private final EksAccessEntryService entries;
    private final EmulatorConfig config;
    private final EksAccessIdentitySigner signer;

    @Inject
    EksWorkerAuthentication(IamService iam, EksService eks, Ec2Service ec2, EksAccessEntryService entries,
                            EmulatorConfig config, EksAccessIdentitySigner signer) {
        this.iam = iam;
        this.eks = eks;
        this.ec2 = ec2;
        this.entries = entries;
        this.config = config;
        this.signer = signer;
    }

    EksWorkerAuthentication(IamService iam, EksService eks, Ec2Service ec2, EksAccessEntryService entries,
                            EmulatorConfig config) {
        this(iam, eks, ec2, entries, config, new EksAccessIdentitySigner());
    }

    Optional<Map<String, Object>> authenticate(EksTokenValidator.VerifiedToken token, String name,
                                               String account, String region, String createdAt) {
        Optional<EksSessionIdentity> session = iam.findEksSessionIdentity(token.accessKeyId());
        boolean instanceSession = session.isPresent() && session.get().instanceId() != null;
        if (!instanceSession && enforcementEnabled(config)) {
            return authenticateByAccessEntry(token, name, account, region, createdAt);
        }
        // Keep the existing non-worker compatibility path. Expired/revoked temporary sessions
        // must never fall through to it after signature validation.
        if (session.isEmpty()) {
            if (IamService.isTemporaryAccessKey(token.accessKeyId())) {
                return Optional.empty();
            }
            // The legacy identity is system:masters, so only a key of the cluster's own account gets it.
            return Optional.ofNullable(token.keyAccountId())
                    .filter(owner -> owner.equals(clusterAccount(account)))
                    .flatMap(owner -> legacyIdentity());
        }
        EksSessionIdentity identity = session.get();
        if (identity.instanceId() == null) {
            return legacyIdentity();
        }
        if (account == null || region == null || createdAt == null || !account.equals(identity.accountId())
                || !region.equals(token.region()) || identity.roleArn() == null || identity.roleId() == null) {
            return Optional.empty();
        }
        Optional<Cluster> cluster = eks.findAuthenticationCluster(account, name)
                .filter(value -> value.getArn() != null && value.getArn().equals(
                        AwsArnUtils.Arn.of("eks", region, account, "cluster/" + name).toString()))
                .filter(value -> createdAt.equals(String.valueOf(value.getCreatedAt())));
        if (cluster.isEmpty()) {
            return Optional.empty();
        }
        String roleName = identity.roleArn().substring(identity.roleArn().lastIndexOf('/') + 1);
        Optional<IamRole> role = iam.findRole(account, roleName)
                .filter(value -> identity.roleArn().equals(value.getArn()) && identity.roleId().equals(value.getRoleId()));
        if (role.isEmpty()) {
            return Optional.empty();
        }
        try {
            if (entries.workerEntry(cluster.get(), account, identity.roleArn(), identity.roleId()).isEmpty()) {
                return Optional.empty();
            }
        } catch (AwsException rejected) {
            return Optional.empty();
        }
        Optional<Instance> instance = ec2.findInstanceForAccount(account, region, identity.instanceId())
                .filter(value -> value.getState() != null && "running".equals(value.getState().getName()))
                .filter(value -> region.equals(value.getRegion()))
                .filter(value -> profileMatches(value, account, roleName));
        if (instance.isEmpty() || instance.get().getPrivateDnsName() == null
                || instance.get().getPrivateDnsName().isBlank()) {
            return Optional.empty();
        }
        return Optional.of(Map.of("username", "system:node:" + instance.get().getPrivateDnsName(),
                "uid", account + ":" + identity.roleId() + ":" + identity.instanceId(),
                "groups", List.of("system:bootstrappers", "system:nodes")));
    }

    /** Whether EKS authenticates and authorizes callers as AWS does: IAM enforcement turns both on. */
    static boolean enforcementEnabled(EmulatorConfig config) {
        return config.services() != null && config.services().iam() != null
                && config.services().iam().enforcementEnabled();
    }

    private Optional<Map<String, Object>> authenticateByAccessEntry(EksTokenValidator.VerifiedToken token,
                                                                    String name, String account, String region,
                                                                    String createdAt) {
        Optional<EksCaller> found = iam.findEksCaller(token.accessKeyId(), token.keyAccountId());
        if (found.isEmpty()) {
            return Optional.empty();
        }
        EksCaller caller = found.get();
        String clusterAccount = clusterAccount(account);
        if (EksCaller.ROOT.equals(caller.kind())) {
            return clusterAccount.equals(caller.accountId()) ? legacyIdentity() : Optional.empty();
        }
        if (!EksCaller.USER.equals(caller.kind()) && !EksCaller.ROLE.equals(caller.kind())) {
            return Optional.empty();
        }
        Optional<Cluster> cluster = authenticationCluster(name, account, region, createdAt);
        if (cluster.isEmpty()) {
            return Optional.empty();
        }
        Cluster value = cluster.get();
        String mode = value.getAccessConfig() == null || value.getAccessConfig().authenticationMode() == null
                ? "CONFIG_MAP" : value.getAccessConfig().authenticationMode();
        if (!"CONFIG_MAP".equals(mode)) {
            Optional<EksAccessEntryService.StoredEntry> entry =
                    entries.standardEntry(value, clusterAccount, caller.principalArn(), caller.principalId());
            if (entry.isPresent()) {
                return Optional.of(identity(value, caller, entry.get().entry().username(),
                        entry.get().entry().kubernetesGroups(), token.accessKeyId(), true));
            }
        }
        if ("CONFIG_MAP".equals(mode) && caller.principalArn().equals(value.getCreatorPrincipalArn())
                && caller.principalId().equals(value.getCreatorPrincipalId())) {
            return Optional.of(identity(value, caller, null, List.of("system:masters"), token.accessKeyId(), false));
        }
        return Optional.empty();
    }

    /**
     * The cluster a scoped webhook path names, created at the instant it gives. An unscoped path predates
     * per-account clusters, so it names the default account's cluster of that name.
     */
    private Optional<Cluster> authenticationCluster(String name, String account, String region, String createdAt) {
        if (account == null) {
            return eks.findAuthenticationCluster(clusterAccount(null), name);
        }
        if (region == null || createdAt == null) {
            return Optional.empty();
        }
        return eks.findAuthenticationCluster(account, name)
                .filter(value -> value.getArn() != null && value.getArn().equals(
                        AwsArnUtils.Arn.of("eks", region, account, "cluster/" + name).toString()))
                .filter(value -> createdAt.equals(String.valueOf(value.getCreatedAt())));
    }

    /**
     * The identity EKS gives a mapped principal: {@code usernameTemplate}, with {@code {{SessionName}}} (the
     * session name with {@code @} replaced by {@code -}) and {@code {{SessionNameRaw}}} filled in, or for null the
     * username an access entry generates (the assumed-role ARN without the role's path, or the user's ARN), and
     * {@code groups}. Like the AWS IAM Authenticator it carries the caller's ARNs, principal id and session name
     * in {@code extra}. For an access entry ({@code accessEntry}) Floci adds the signed principal ARN the
     * authorization webhook reads the entry's access policies by; the hidden creator mapping carries none.
     */
    private Map<String, Object> identity(Cluster cluster, EksCaller caller, String usernameTemplate,
                                         List<String> groups, String accessKeyId, boolean accessEntry) {
        String sessionName = caller.sessionName() == null ? "" : caller.sessionName();
        AwsArnUtils.Arn principal = AwsArnUtils.parse(caller.principalArn());
        String callerArn = caller.principalArn();
        String canonicalArn = caller.principalArn();
        String generatedUsername = caller.principalArn();
        if (EksCaller.ROLE.equals(caller.kind())) {
            String roleName = callerArn.substring(callerArn.lastIndexOf('/') + 1);
            callerArn = AwsArnUtils.Arn.global(principal.partition(), "sts", principal.accountId(),
                    "assumed-role/" + roleName + "/" + sessionName).toString();
            canonicalArn = AwsArnUtils.Arn.global(principal.partition(), "iam", principal.accountId(),
                    "role/" + roleName).toString();
            generatedUsername = AwsArnUtils.Arn.global(principal.partition(), "sts", principal.accountId(),
                    "assumed-role/" + roleName + "/{{SessionName}}").toString();
        }
        String username = (usernameTemplate == null ? generatedUsername : usernameTemplate)
                .replace("{{SessionNameRaw}}", sessionName)
                .replace("{{SessionName}}", sessionName.replace('@', '-'));
        Map<String, List<String>> extra = new LinkedHashMap<>();
        extra.put("accessKeyId", List.of(accessKeyId));
        extra.put("arn", List.of(callerArn));
        extra.put("canonicalArn", List.of(canonicalArn));
        extra.put("principalId", List.of(caller.principalId()));
        extra.put("sessionName", List.of(sessionName));
        if (accessEntry) {
            extra.put(PRINCIPAL_ARN_EXTRA, List.of(caller.principalArn()));
            extra.put(SIGNATURE_EXTRA, List.of(signer.sign(cluster.getArn(), String.valueOf(cluster.getCreatedAt()),
                    caller.principalArn(), caller.principalId())));
        }
        Map<String, Object> user = new LinkedHashMap<>();
        user.put("username", username);
        user.put("uid", "aws-iam-authenticator:" + principal.accountId() + ":" + caller.principalId());
        user.put("groups", groups == null ? List.of() : List.copyOf(groups));
        user.put("extra", extra);
        return user;
    }

    private boolean profileMatches(Instance instance, String account, String roleName) {
        String arn = instance.getIamInstanceProfileArn();
        if (!AwsArnUtils.isArnFor(arn, "iam")) {
            return false;
        }
        AwsArnUtils.Arn parsed = AwsArnUtils.parse(arn);
        if (!account.equals(parsed.accountId()) || !parsed.resource().startsWith("instance-profile/")) {
            return false;
        }
        return iam.findInstanceProfile(account, arn.substring(arn.lastIndexOf('/') + 1))
                .filter(profile -> arn.equals(profile.getArn()))
                .filter(profile -> List.of(roleName).equals(profile.getRoleNames())).isPresent();
    }

    /** Unscoped webhook paths predate per-account clusters, so they serve the default account. */
    private String clusterAccount(String account) {
        return account != null ? account : config.defaultAccountId();
    }

    private static Optional<Map<String, Object>> legacyIdentity() {
        return Optional.of(Map.of("username", "floci:aws-iam", "uid", "floci-aws-iam",
                "groups", List.of("system:masters")));
    }
}
