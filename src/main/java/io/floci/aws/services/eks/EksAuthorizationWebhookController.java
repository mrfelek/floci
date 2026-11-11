package io.floci.aws.services.eks;

import io.floci.aws.config.EmulatorConfig;
import io.floci.aws.core.common.AwsArnUtils;
import io.floci.aws.services.eks.model.Cluster;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Kubernetes authorization webhook for k3s-backed EKS clusters: applies the access policies associated with
 * the caller's access entry, as EKS's own authorizer does.
 *
 * <p>The k3s API server asks it (see {@code EksClusterManager}) after RBAC, with a {@code SubjectAccessReview}
 * for every request RBAC did not allow. It answers allowed when one of the entry's policies allows the request
 * in its scope, and otherwise has no opinion: access policies never deny, so the API server then refuses the
 * request as RBAC left it. The entry is the one the token webhook mapped the caller to, which it names and
 * signs in the user's {@code extra}. Without IAM enforcement the token webhook maps no entries, and this
 * webhook has no opinion on anything.
 *
 * <p>This is Floci plumbing under the {@code _floci/...} namespace, not an AWS API.
 */
@ApplicationScoped
@Path("_floci/eks/clusters/{clusterName}/authorization-webhook")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class EksAuthorizationWebhookController {

    private static final Logger LOG = Logger.getLogger(EksAuthorizationWebhookController.class);

    private final EksService eks;
    private final EksAccessEntryService entries;
    private final EksAccessIdentitySigner signer;
    private final EksAccessPolicyAuthorizer authorizer;
    private final EmulatorConfig config;

    @Inject
    public EksAuthorizationWebhookController(EksService eks, EksAccessEntryService entries,
                                             EksAccessIdentitySigner signer, EksAccessPolicyCatalog catalog,
                                             EmulatorConfig config) {
        this.eks = eks;
        this.entries = entries;
        this.signer = signer;
        this.authorizer = new EksAccessPolicyAuthorizer(catalog);
        this.config = config;
    }

    @POST
    @Path("scope/{accountId}/{region}/{createdAt}")
    public Response review(@PathParam("clusterName") String clusterName, @PathParam("accountId") String accountId,
                           @PathParam("region") String region, @PathParam("createdAt") String createdAt,
                           Map<String, Object> review) {
        // The response apiVersion must match the request's, as for the token webhook.
        String apiVersion = review != null && review.get("apiVersion") instanceof String v
                ? v : "authorization.k8s.io/v1";
        Optional<String> policy = EksWorkerAuthentication.enforcementEnabled(config)
                ? allowingPolicy(clusterName, accountId, region, createdAt, review) : Optional.empty();
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("allowed", policy.isPresent());
        policy.ifPresent(name -> status.put("reason", "allowed by EKS access policy " + name));
        return Response.ok(Map.of("apiVersion", apiVersion, "kind", "SubjectAccessReview", "status", status))
                .build();
    }

    private Optional<String> allowingPolicy(String clusterName, String accountId, String region, String createdAt,
                                            Map<String, Object> review) {
        Map<String, Object> spec = map(review == null ? null : review.get("spec"));
        Map<String, Object> extra = map(spec.get("extra"));
        String principalArn = firstValue(extra, EksWorkerAuthentication.PRINCIPAL_ARN_EXTRA);
        String principalId = firstValue(extra, "principalId");
        String signature = firstValue(extra, EksWorkerAuthentication.SIGNATURE_EXTRA);
        if (principalArn == null) {
            return Optional.empty();
        }
        String clusterArn = AwsArnUtils.Arn.of("eks", region, accountId, "cluster/" + clusterName).toString();
        if (!signer.verify(signature, clusterArn, createdAt, principalArn, principalId)) {
            LOG.debugv("EKS authorization-webhook: ignoring an unsigned or impersonated identity on cluster {0}",
                    clusterName);
            return Optional.empty();
        }
        Optional<Cluster> cluster = eks.findAuthenticationCluster(accountId, clusterName)
                .filter(value -> clusterArn.equals(value.getArn()))
                .filter(value -> createdAt.equals(String.valueOf(value.getCreatedAt())));
        if (cluster.isEmpty()) {
            return Optional.empty();
        }
        Optional<EksAccessEntryService.StoredEntry> entry =
                entries.standardEntry(cluster.get(), accountId, principalArn, principalId);
        if (entry.isEmpty()) {
            return Optional.empty();
        }
        return authorizer.allowingPolicy(entry.get().accessPolicies(), request(spec));
    }

    private static EksAccessPolicyAuthorizer.Request request(Map<String, Object> spec) {
        Map<String, Object> resource = map(spec.get("resourceAttributes"));
        if (!resource.isEmpty()) {
            return EksAccessPolicyAuthorizer.Request.resource(string(resource, "verb"), string(resource, "namespace"),
                    string(resource, "group"), string(resource, "resource"), string(resource, "subresource"),
                    string(resource, "name"));
        }
        Map<String, Object> nonResource = map(spec.get("nonResourceAttributes"));
        return EksAccessPolicyAuthorizer.Request.nonResource(string(nonResource, "verb"),
                string(nonResource, "path"));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value) {
        return value instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
    }

    private static String string(Map<String, Object> map, String key) {
        return map.get(key) instanceof String s ? s : null;
    }

    /** The first value of an {@code extra} attribute; the API server may send its key in another case. */
    private static String firstValue(Map<String, Object> extra, String key) {
        for (Map.Entry<String, Object> attribute : extra.entrySet()) {
            if (attribute.getKey().equalsIgnoreCase(key) && attribute.getValue() instanceof List<?> values
                    && !values.isEmpty() && values.get(0) instanceof String value) {
                return value;
            }
        }
        return null;
    }
}
