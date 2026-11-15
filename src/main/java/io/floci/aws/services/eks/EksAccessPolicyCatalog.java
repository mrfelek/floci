package io.floci.aws.services.eks;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.aws.core.common.PaginatedResult;
import io.floci.aws.core.common.RegionResolver;
import io.floci.aws.core.common.VendoredResources;
import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.ArrayList;
import java.util.List;

/**
 * The EKS cluster access policies, vendored from EKS ListAccessPolicies into {@code eks/access-policies.json} by
 * {@code tools/aws/regen_eks_access_policies.py}. ListAccessPolicies answers from it. An access policy's ARN names
 * no Region and the account {@code aws}, so each is built in the caller's partition.
 */
@ApplicationScoped
public class EksAccessPolicyCatalog {

    private static final List<String> NAMES = VendoredResources.read("eks/access-policies.json",
            "EKS access policy catalog", in -> names(new ObjectMapper().readTree(in)));

    private final RegionResolver regionResolver;

    @Inject
    public EksAccessPolicyCatalog(RegionResolver regionResolver) {
        this.regionResolver = regionResolver;
    }

    @RegisterForReflection
    public record AccessPolicy(String name, String arn) {}

    private static List<String> names(JsonNode catalog) {
        List<String> names = new ArrayList<>();
        catalog.path("accessPolicies").forEach(policy -> names.add(policy.path("name").asText()));
        return List.copyOf(names);
    }

    /**
     * One page of the access policies, in name order, as ListAccessPolicies answers them, with the messages AWS
     * gives for a {@code maxResults} or {@code nextToken} it refuses.
     */
    public PaginatedResult<AccessPolicy> list(Integer maxResults, String nextToken) {
        List<AccessPolicy> all = NAMES.stream().map(name -> new AccessPolicy(name,
                regionResolver.buildGlobalArn("eks", "aws", "cluster-access-policy/" + name))).toList();
        return EksAccessEntryService.page(all, AccessPolicy::name, maxResults, nextToken, "access-policies",
                "maxResults must be a number between 1 and 100.",
                "The specified nextToken is invalid: unrecognized format.");
    }
}
