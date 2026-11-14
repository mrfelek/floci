package io.floci.aws.services.eks;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.aws.core.common.AwsArnUtils;
import io.floci.aws.core.common.AwsException;
import io.floci.aws.core.common.PaginatedResult;
import io.floci.aws.core.common.Pagination;
import io.floci.aws.core.common.RegionResolver;
import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.List;

/**
 * The EKS cluster access policies, vendored from the EKS documentation into {@code eks/access-policies.json} by
 * {@code tools/aws/regen_eks_access_policies.py}. ListAccessPolicies answers from it. An access policy's ARN names
 * no Region and the account {@code aws} in every partition, so each is built in the caller's partition.
 */
@ApplicationScoped
public class EksAccessPolicyCatalog {

    private static final String CATALOG_RESOURCE_NAME = "eks/access-policies.json";

    private final RegionResolver regionResolver;
    private final List<String> names;

    @Inject
    public EksAccessPolicyCatalog(RegionResolver regionResolver) {
        this(regionResolver, load());
    }

    EksAccessPolicyCatalog(RegionResolver regionResolver, List<String> names) {
        this.regionResolver = regionResolver;
        this.names = List.copyOf(names);
    }

    @RegisterForReflection
    @JsonIgnoreProperties(ignoreUnknown = true)
    record CatalogFile(List<Entry> policies) {}

    @RegisterForReflection
    @JsonIgnoreProperties(ignoreUnknown = true)
    record Entry(String name) {}

    @RegisterForReflection
    public record AccessPolicy(String name, String arn) {}

    public record Page(List<AccessPolicy> accessPolicies, String nextToken) {}

    private static List<String> load() {
        try (InputStream is = Thread.currentThread().getContextClassLoader()
                .getResourceAsStream(CATALOG_RESOURCE_NAME)) {
            if (is == null) {
                throw new IllegalStateException("EKS access policy catalog not found: " + CATALOG_RESOURCE_NAME);
            }
            return new ObjectMapper().readValue(is, CatalogFile.class).policies().stream().map(Entry::name).toList();
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to load the EKS access policy catalog", e);
        }
    }

    /** One page of the access policies, in name order, as ListAccessPolicies answers them. */
    public Page list(Integer maxResults, String nextToken) {
        String partition = regionResolver.getPartition();
        List<AccessPolicy> all = names.stream().map(name -> new AccessPolicy(name,
                AwsArnUtils.Arn.global(partition, "eks", "aws", "cluster-access-policy/" + name).toString())).toList();
        PaginatedResult<AccessPolicy> page = Pagination.paginate(all, AccessPolicy::name,
                EksAccessEntryService.pageSize(maxResults), nextToken, "access-policies",
                token -> new AwsException("InvalidParameterException", "Invalid nextToken", 400));
        return new Page(page.items(), page.nextToken());
    }
}
