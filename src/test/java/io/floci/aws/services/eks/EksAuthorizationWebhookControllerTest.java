package io.floci.aws.services.eks;

import io.floci.aws.config.EmulatorConfig;
import io.floci.aws.core.storage.InMemoryStorage;
import io.floci.aws.services.eks.model.AccessConfig;
import io.floci.aws.services.eks.model.AccessScope;
import io.floci.aws.services.eks.model.AssociateAccessPolicyRequest;
import io.floci.aws.services.eks.model.Cluster;
import io.floci.aws.services.eks.model.ClusterStatus;
import io.floci.aws.services.eks.model.CreateAccessEntryRequest;
import io.floci.aws.services.iam.IamService;
import io.floci.aws.services.iam.model.IamRole;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class EksAuthorizationWebhookControllerTest {
    private static final String ACCOUNT = "123456789012";
    private static final String REGION = "eu-west-1";
    private static final Instant CREATED = Instant.parse("2026-11-11T00:00:00Z");
    private static final String ROLE = "arn:aws:iam::" + ACCOUNT + ":role/readers";
    private static final String ROLE_ID = "AROAREADERS";

    private final IamService iam = mock(IamService.class);
    private final EksService eks = mock(EksService.class);
    private final EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
    private final EksAccessPolicyCatalog catalog = new EksAccessPolicyCatalog();
    private final EksAccessEntryService entries = new EksAccessEntryService(new InMemoryStorage<>(), iam);
    private final EksAccessIdentitySigner signer = new EksAccessIdentitySigner(new byte[32]);
    private final EksAuthorizationWebhookController webhook =
            new EksAuthorizationWebhookController(eks, entries, signer, catalog, config);
    private final Cluster cluster = new Cluster();

    @BeforeEach
    void setUp() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);
        cluster.setName("demo");
        cluster.setArn("arn:aws:eks:" + REGION + ":" + ACCOUNT + ":cluster/demo");
        cluster.setCreatedAt(CREATED);
        cluster.setStatus(ClusterStatus.ACTIVE);
        cluster.setAccessConfig(new AccessConfig("API", true));
        when(eks.findAuthenticationCluster(ACCOUNT, "demo")).thenReturn(Optional.of(cluster));
        when(iam.findRole(ACCOUNT, "readers")).thenReturn(Optional.of(new IamRole(ROLE_ID, "readers", "/", ROLE, "{}")));
        entries.create(cluster, new CreateAccessEntryRequest(ROLE, null, null, null, null, null));
        entries.associate(cluster, ROLE, new AssociateAccessPolicyRequest(
                EksAccessPolicyCatalog.arn("aws", "AmazonEKSViewPolicy"), new AccessScope("namespace", List.of("team-a"))));
    }

    @Test
    void allowsWhatTheEntrysPoliciesAllowInTheirScope() {
        Map<?, ?> status = review(signedExtra(), pods("list", "team-a"));
        assertEquals(true, status.get("allowed"));
        assertEquals("allowed by EKS access policy AmazonEKSViewPolicy", status.get("reason"));
    }

    @Test
    void hasNoOpinionOutsideThePoliciesOrTheirScope() {
        assertEquals(Map.of("allowed", false), review(signedExtra(), pods("delete", "team-a")));
        assertEquals(Map.of("allowed", false), review(signedExtra(), pods("list", "team-b")));
        assertEquals(Map.of("allowed", false), review(signedExtra(),
                Map.of("nonResourceAttributes", Map.of("verb", "get", "path", "/healthz"))));
    }

    @Test
    void ignoresAnIdentityTheTokenWebhookDidNotSign() {
        Map<String, Object> forged = new HashMap<>(signedExtra());
        forged.put(EksWorkerAuthentication.SIGNATURE_EXTRA, List.of("00"));
        assertEquals(Map.of("allowed", false), review(forged, pods("list", "team-a")));
        Map<String, Object> unsigned = new HashMap<>(signedExtra());
        unsigned.remove(EksWorkerAuthentication.SIGNATURE_EXTRA);
        assertEquals(Map.of("allowed", false), review(unsigned, pods("list", "team-a")));
    }

    @Test
    void readsExtraKeysWhateverTheirCase() {
        Map<String, Object> extra = new HashMap<>();
        signedExtra().forEach((key, value) -> extra.put(key.toUpperCase(), value));
        assertEquals(true, review(extra, pods("get", "team-a")).get("allowed"));
    }

    @Test
    void appliesNoPoliciesWithoutIamEnforcement() {
        when(config.services().iam().enforcementEnabled()).thenReturn(false);
        assertEquals(Map.of("allowed", false), review(signedExtra(), pods("list", "team-a")));
    }

    @Test
    void echoesTheReviewsApiVersion() {
        Map<?, ?> response = (Map<?, ?>) webhook.review("demo", ACCOUNT, REGION, CREATED.toString(),
                Map.of("apiVersion", "authorization.k8s.io/v1beta1", "spec", Map.of())).getEntity();
        assertEquals("authorization.k8s.io/v1beta1", response.get("apiVersion"));
        assertEquals("SubjectAccessReview", response.get("kind"));
    }

    private Map<String, Object> signedExtra() {
        return Map.of(
                "principalId", List.of(ROLE_ID),
                EksWorkerAuthentication.PRINCIPAL_ARN_EXTRA, List.of(ROLE),
                EksWorkerAuthentication.SIGNATURE_EXTRA, List.of(signer.sign(cluster.getArn(), CREATED.toString(),
                        ROLE, ROLE_ID)));
    }

    private static Map<String, Object> pods(String verb, String namespace) {
        return Map.of("resourceAttributes", Map.of("verb", verb, "namespace", namespace, "group", "",
                "resource", "pods"));
    }

    private Map<?, ?> review(Map<String, Object> extra, Map<String, Object> attributes) {
        Map<String, Object> spec = new HashMap<>(attributes);
        spec.put("user", "arn:aws:sts::" + ACCOUNT + ":assumed-role/readers/alice");
        spec.put("extra", extra);
        Map<?, ?> response = (Map<?, ?>) webhook.review("demo", ACCOUNT, REGION, CREATED.toString(),
                Map.of("apiVersion", "authorization.k8s.io/v1", "spec", spec)).getEntity();
        return (Map<?, ?>) response.get("status");
    }
}
