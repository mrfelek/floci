package io.floci.aws.services.eks;

import io.floci.aws.config.EmulatorConfig;
import io.floci.aws.core.storage.InMemoryStorage;
import io.floci.aws.services.ec2.Ec2Service;
import io.floci.aws.services.eks.model.AccessConfig;
import io.floci.aws.services.eks.model.Cluster;
import io.floci.aws.services.eks.model.ClusterStatus;
import io.floci.aws.services.eks.model.CreateAccessEntryRequest;
import io.floci.aws.services.iam.IamService;
import io.floci.aws.services.iam.IamService.EksCaller;
import io.floci.aws.services.iam.model.IamRole;
import io.floci.aws.services.iam.model.IamUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** With IAM enforcement on, the token webhook authenticates IAM principals by their access entry, as EKS does. */
class EksAccessEntryAuthenticationTest {
    private static final String ACCOUNT = "123456789012";
    private static final String OTHER_ACCOUNT = "111122223333";
    private static final String REGION = "eu-west-1";
    private static final String KEY = "ASIASESSION";
    private static final Instant CREATED = Instant.parse("2026-11-11T00:00:00Z");
    private static final String ROLE = "arn:aws:iam::" + ACCOUNT + ":role/team/dev";
    private static final String ROLE_ID = "AROADEV";

    private final IamService iam = mock(IamService.class);
    private final EksService eks = mock(EksService.class);
    private final EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
    private final EksAccessEntryService entries = new EksAccessEntryService(new InMemoryStorage<>(), iam);
    private final EksAccessIdentitySigner signer = new EksAccessIdentitySigner(new byte[32]);
    private final EksWorkerAuthentication auth =
            new EksWorkerAuthentication(iam, eks, mock(Ec2Service.class), entries, config, signer);
    private final Cluster cluster = new Cluster();

    @BeforeEach
    void setUp() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);
        when(config.defaultAccountId()).thenReturn("000000000000");
        cluster.setName("demo");
        cluster.setArn("arn:aws:eks:" + REGION + ":" + ACCOUNT + ":cluster/demo");
        cluster.setCreatedAt(CREATED);
        cluster.setStatus(ClusterStatus.ACTIVE);
        cluster.setAccessConfig(new AccessConfig("API", true));
        when(eks.findAuthenticationCluster(ACCOUNT, "demo")).thenReturn(Optional.of(cluster));
        when(iam.findEksSessionIdentity(KEY)).thenReturn(Optional.empty());
        when(iam.findRole(ACCOUNT, "dev")).thenReturn(Optional.of(new IamRole(ROLE_ID, "dev", "/team/", ROLE, "{}")));
    }

    @Test
    void roleSessionGetsItsEntrysUsernameAndGroups() {
        entries.create(cluster, new CreateAccessEntryRequest(ROLE, null, null, List.of("developers"), null, null));
        caller(new EksCaller(EksCaller.ROLE, ACCOUNT, ROLE, ROLE_ID, "alice@example.com"));

        Map<String, Object> user = authenticate().orElseThrow();

        // The generated username drops the role's path and fills in the session name, "@" becoming "-".
        assertEquals("arn:aws:sts::" + ACCOUNT + ":assumed-role/dev/alice-example.com", user.get("username"));
        assertEquals(List.of("developers"), user.get("groups"));
        assertEquals("aws-iam-authenticator:" + ACCOUNT + ":" + ROLE_ID, user.get("uid"));
        Map<?, ?> extra = (Map<?, ?>) user.get("extra");
        assertEquals(List.of("arn:aws:sts::" + ACCOUNT + ":assumed-role/dev/alice@example.com"), extra.get("arn"));
        assertEquals(List.of("arn:aws:iam::" + ACCOUNT + ":role/dev"), extra.get("canonicalArn"));
        assertEquals(List.of(ROLE), extra.get(EksWorkerAuthentication.PRINCIPAL_ARN_EXTRA));
        assertEquals(List.of(signer.sign(cluster.getArn(), CREATED.toString(), ROLE, ROLE_ID)),
                extra.get(EksWorkerAuthentication.SIGNATURE_EXTRA));
    }

    @Test
    void customUsernameKeepsTheRawSessionName() {
        entries.create(cluster, new CreateAccessEntryRequest(ROLE, null, "dev:{{SessionNameRaw}}", null, null, null));
        caller(new EksCaller(EksCaller.ROLE, ACCOUNT, ROLE, ROLE_ID, "alice@example.com"));

        Map<String, Object> user = authenticate().orElseThrow();

        assertEquals("dev:alice@example.com", user.get("username"));
        assertEquals(List.of(), user.get("groups"));
    }

    @Test
    void principalWithoutAnEntryIsNotAuthenticated() {
        caller(new EksCaller(EksCaller.ROLE, ACCOUNT, ROLE, ROLE_ID, "alice"));
        assertTrue(authenticate().isEmpty());
    }

    @Test
    void roleCreatedAgainUnderTheSameArnIsNotAuthenticated() {
        entries.create(cluster, new CreateAccessEntryRequest(ROLE, null, null, null, null, null));
        caller(new EksCaller(EksCaller.ROLE, ACCOUNT, ROLE, "AROANEWID", "alice"));
        assertTrue(authenticate().isEmpty());
    }

    @Test
    void principalOfAnotherAccountIsAuthenticatedByItsEntry() {
        String otherRole = "arn:aws:iam::" + OTHER_ACCOUNT + ":role/ci";
        when(iam.findRole(OTHER_ACCOUNT, "ci")).thenReturn(Optional.of(new IamRole("AROACI", "ci", "/", otherRole, "{}")));
        entries.create(cluster, new CreateAccessEntryRequest(otherRole, null, null, List.of("ci"), null, null));
        caller(new EksCaller(EksCaller.ROLE, OTHER_ACCOUNT, otherRole, "AROACI", "pipeline"));

        assertEquals(List.of("ci"), authenticate().orElseThrow().get("groups"));
    }

    @Test
    void iamUserIsAuthenticatedAsItsArn() {
        String userArn = "arn:aws:iam::" + ACCOUNT + ":user/ops/bob";
        when(iam.findUser(ACCOUNT, "bob")).thenReturn(Optional.of(new IamUser("AIDABOB", "bob", "/ops/", userArn)));
        entries.create(cluster, new CreateAccessEntryRequest(userArn, null, null, null, null, null));
        caller(new EksCaller(EksCaller.USER, ACCOUNT, userArn, "AIDABOB", null));

        Map<String, Object> user = authenticate().orElseThrow();

        assertEquals(userArn, user.get("username"));
        assertEquals(List.of(userArn), ((Map<?, ?>) user.get("extra")).get("canonicalArn"));
    }

    @Test
    void accountRootKeepsTheAdministratorIdentityInItsOwnAccountOnly() {
        caller(new EksCaller(EksCaller.ROOT, ACCOUNT, null, null, null));
        assertEquals(List.of("system:masters"), authenticate().orElseThrow().get("groups"));
        caller(new EksCaller(EksCaller.ROOT, OTHER_ACCOUNT, null, null, null));
        assertTrue(authenticate().isEmpty());
    }

    @Test
    void federatedAndDelegatedCallersAreNotAuthenticated() {
        caller(new EksCaller(EksCaller.OTHER, ACCOUNT, null, null, null));
        assertTrue(authenticate().isEmpty());
    }

    @Test
    void clusterCreatedAtAnotherInstantDoesNotAuthenticate() {
        entries.create(cluster, new CreateAccessEntryRequest(ROLE, null, null, null, null, null));
        caller(new EksCaller(EksCaller.ROLE, ACCOUNT, ROLE, ROLE_ID, "alice"));
        assertTrue(auth.authenticate(token(), "demo", ACCOUNT, REGION, "2026-01-01T00:00:00Z").isEmpty());
    }

    @Test
    void configMapModeMapsOnlyTheCreatorToSystemMasters() {
        cluster.setAccessConfig(new AccessConfig("CONFIG_MAP", true));
        cluster.setCreatorPrincipalArn(ROLE);
        cluster.setCreatorPrincipalId(ROLE_ID);
        caller(new EksCaller(EksCaller.ROLE, ACCOUNT, ROLE, ROLE_ID, "terraform"));
        Map<String, Object> creator = authenticate().orElseThrow();
        assertEquals(List.of("system:masters"), creator.get("groups"));
        assertEquals("arn:aws:sts::" + ACCOUNT + ":assumed-role/dev/terraform", creator.get("username"));
        // The creator's mapping carries no access policies, so nothing is signed for the authorization webhook.
        assertTrue(!((Map<?, ?>) creator.get("extra")).containsKey(EksWorkerAuthentication.SIGNATURE_EXTRA));

        // Floci does not read the aws-auth ConfigMap, so no one else is mapped in this mode.
        caller(new EksCaller(EksCaller.ROLE, ACCOUNT, "arn:aws:iam::" + ACCOUNT + ":role/ops", "AROAOPS", "carol"));
        assertTrue(authenticate().isEmpty());
        // A role created again under the creator's ARN is not the creator.
        caller(new EksCaller(EksCaller.ROLE, ACCOUNT, ROLE, "AROANEWID", "terraform"));
        assertTrue(authenticate().isEmpty());
    }

    @Test
    void accessEntryModesDoNotMapTheCreatorWithoutItsEntry() {
        cluster.setCreatorPrincipalArn(ROLE);
        cluster.setCreatorPrincipalId(ROLE_ID);
        caller(new EksCaller(EksCaller.ROLE, ACCOUNT, ROLE, ROLE_ID, "terraform"));
        assertTrue(authenticate().isEmpty());
        cluster.setAccessConfig(new AccessConfig("API_AND_CONFIG_MAP", false));
        assertTrue(authenticate().isEmpty());
    }

    private void caller(EksCaller caller) {
        when(iam.findEksCaller(KEY, null)).thenReturn(Optional.of(caller));
    }

    private Optional<Map<String, Object>> authenticate() {
        return auth.authenticate(token(), "demo", ACCOUNT, REGION, CREATED.toString());
    }

    private static EksTokenValidator.VerifiedToken token() {
        return new EksTokenValidator.VerifiedToken(KEY, REGION, null);
    }
}
