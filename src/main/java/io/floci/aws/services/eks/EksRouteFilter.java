package io.floci.aws.services.eks;

import io.floci.aws.core.common.ResolvedServiceCatalog;
import io.floci.aws.core.common.SignedServiceRoute;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.ext.Provider;

import java.util.Set;

/**
 * Routes EKS's account-level {@code GET /access-policies} (ListAccessPolicies) to EKS only when the request is
 * signed for EKS, so S3's path-style routes keep serving a bucket of that name.
 */
@Provider
@PreMatching
public class EksRouteFilter implements ContainerRequestFilter {
    static final String INTERNAL_PREFIX = "/_eks";
    private static final Set<String> PUBLIC_PATHS = Set.of("/access-policies");
    private final SignedServiceRoute route;

    @Inject
    public EksRouteFilter(ResolvedServiceCatalog catalog) {
        route = new SignedServiceRoute(catalog, "eks", INTERNAL_PREFIX, PUBLIC_PATHS::contains);
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        route.apply(ctx);
    }
}
