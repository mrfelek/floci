package io.floci.aws.services.eks;

import io.floci.aws.services.eks.model.AccessScope;
import io.floci.aws.services.eks.model.AssociatedAccessPolicy;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Decides whether an access entry's associated access policies allow a Kubernetes request, as EKS's
 * authorizer does: policies only allow, so a request no policy allows is left to Kubernetes RBAC.
 *
 * <p>Rules match as Kubernetes RBAC rules do (verbs, API groups, resources, a subresource of any resource,
 * resource names, non-resource URLs with a trailing {@code *}). A cluster scope applies a policy to every
 * request. A namespace scope applies it as a RoleBinding in each namespace it names would: to requests in a
 * matching namespace only, never to cluster-scoped resources or non-resource URLs. A namespace pattern may
 * use {@code *} as a wildcard ({@code dev-*}).
 */
final class EksAccessPolicyAuthorizer {

    private final EksAccessPolicyCatalog catalog;

    EksAccessPolicyAuthorizer(EksAccessPolicyCatalog catalog) {
        this.catalog = catalog;
    }

    /**
     * A Kubernetes request's attributes, as a SubjectAccessReview carries them. For a resource request
     * {@code path} is null; for a non-resource request only {@code verb} and {@code path} are set.
     */
    record Request(String verb, String namespace, String apiGroup, String resource, String subresource,
                   String name, String path) {

        static Request resource(String verb, String namespace, String apiGroup, String resource,
                                String subresource, String name) {
            return new Request(verb, namespace, apiGroup, resource, subresource, name, null);
        }

        static Request nonResource(String verb, String path) {
            return new Request(verb, null, null, null, null, null, path);
        }

        boolean isResourceRequest() {
            return path == null;
        }
    }

    /** The name of the first associated policy that allows {@code request}, or empty when none does. */
    Optional<String> allowingPolicy(List<AssociatedAccessPolicy> policies, Request request) {
        for (AssociatedAccessPolicy association : policies) {
            Optional<EksAccessPolicyCatalog.Policy> policy = catalog.forArn(association.policyArn());
            if (policy.isPresent() && inScope(association.accessScope(), request)
                    && policy.get().rules().stream().anyMatch(rule -> allows(rule, request))) {
                return Optional.of(policy.get().name());
            }
        }
        return Optional.empty();
    }

    static boolean inScope(AccessScope scope, Request request) {
        if (scope == null || "cluster".equals(scope.type())) {
            return true;
        }
        if (!"namespace".equals(scope.type()) || !request.isResourceRequest()
                || request.namespace() == null || request.namespace().isEmpty()) {
            return false;
        }
        return scope.namespaces() != null
                && scope.namespaces().stream().anyMatch(pattern -> namespaceMatches(pattern, request.namespace()));
    }

    static boolean namespaceMatches(String pattern, String namespace) {
        if (pattern == null) {
            return false;
        }
        if (pattern.indexOf('*') < 0) {
            return pattern.equals(namespace);
        }
        StringBuilder regex = new StringBuilder();
        for (String part : pattern.split("\\*", -1)) {
            if (!regex.isEmpty()) {
                regex.append(".*");
            }
            regex.append(Pattern.quote(part));
        }
        return Pattern.matches(regex.toString(), namespace);
    }

    static boolean allows(EksAccessPolicyCatalog.Rule rule, Request request) {
        if (!matchesWildcard(rule.verbs(), request.verb())) {
            return false;
        }
        if (!request.isResourceRequest()) {
            return rule.nonResourceURLs().stream().anyMatch(url -> urlMatches(url, request.path()));
        }
        return matchesWildcard(rule.apiGroups(), request.apiGroup() == null ? "" : request.apiGroup())
                && resourceMatches(rule.resources(), request.resource(), request.subresource())
                && (rule.resourceNames().isEmpty() || rule.resourceNames().contains(request.name()));
    }

    private static boolean matchesWildcard(List<String> values, String value) {
        return values.contains("*") || (value != null && values.contains(value));
    }

    private static boolean resourceMatches(List<String> ruleResources, String resource, String subresource) {
        if (resource == null) {
            return false;
        }
        boolean hasSubresource = subresource != null && !subresource.isEmpty();
        String combined = hasSubresource ? resource + "/" + subresource : resource;
        for (String ruleResource : ruleResources) {
            if (ruleResource.equals("*") || ruleResource.equals(combined)
                    || (hasSubresource && ruleResource.equals("*/" + subresource))) {
                return true;
            }
        }
        return false;
    }

    private static boolean urlMatches(String ruleUrl, String path) {
        if (path == null) {
            return false;
        }
        if (ruleUrl.equals("*") || ruleUrl.equals(path)) {
            return true;
        }
        return ruleUrl.endsWith("*") && path.startsWith(ruleUrl.substring(0, ruleUrl.length() - 1));
    }
}
