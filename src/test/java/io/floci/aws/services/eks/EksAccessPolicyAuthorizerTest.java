package io.floci.aws.services.eks;

import io.floci.aws.services.eks.EksAccessPolicyAuthorizer.Request;
import io.floci.aws.services.eks.model.AccessScope;
import io.floci.aws.services.eks.model.AssociatedAccessPolicy;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Access policies against the rules AWS documents for them, in the catalog Floci ships. */
class EksAccessPolicyAuthorizerTest {

    private final EksAccessPolicyCatalog catalog = new EksAccessPolicyCatalog();
    private final EksAccessPolicyAuthorizer authorizer = new EksAccessPolicyAuthorizer(catalog);

    @Test
    void catalogListsEveryDocumentedPolicyWithItsRules() {
        assertEquals(28, catalog.names().size());
        assertEquals("AmazonEKSAdminPolicy", catalog.names().get(0));
        assertFalse(catalog.find("AmazonEKSClusterAdminPolicy").orElseThrow().rules().isEmpty());
        // AWS describes the Auto Mode policies in prose only, so they carry no rules and grant nothing here.
        assertTrue(catalog.find("AmazonEKSAutoNodePolicy").orElseThrow().rules().isEmpty());
        assertEquals("arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy",
                EksAccessPolicyCatalog.arn("aws", "AmazonEKSViewPolicy"));
        assertEquals("AmazonEKSViewPolicy",
                catalog.forArn("arn:aws-cn:eks::aws:cluster-access-policy/AmazonEKSViewPolicy").orElseThrow().name());
        assertTrue(catalog.forArn("arn:aws:eks::aws:cluster-access-policy/NoSuchPolicy").isEmpty());
    }

    @Test
    void viewPolicyReadsButNeitherWritesNorReadsSecrets() {
        List<AssociatedAccessPolicy> view = List.of(association("AmazonEKSViewPolicy", cluster()));
        assertEquals(Optional.of("AmazonEKSViewPolicy"), allowing(view, pods("get", "team-a")));
        assertEquals(Optional.of("AmazonEKSViewPolicy"), allowing(view, pods("list", "")));
        assertTrue(allowing(view, pods("delete", "team-a")).isEmpty());
        assertTrue(allowing(view, Request.resource("get", "team-a", "", "secrets", null, "token")).isEmpty());
        assertEquals(Optional.of("AmazonEKSViewPolicy"),
                allowing(view, Request.resource("get", "team-a", "", "pods", "log", "web")));
        assertTrue(allowing(view, Request.resource("create", "team-a", "", "pods", "exec", "web")).isEmpty());
    }

    @Test
    void editPolicyExecsIntoPodsAndWritesSecrets() {
        List<AssociatedAccessPolicy> edit = List.of(association("AmazonEKSEditPolicy", cluster()));
        assertTrue(allowing(edit, Request.resource("create", "team-a", "", "pods", "exec", "web")).isPresent());
        assertTrue(allowing(edit, Request.resource("update", "team-a", "", "secrets", null, "token")).isPresent());
        // Edit grants no RBAC objects; Admin does.
        assertTrue(allowing(edit, Request.resource("create", "team-a", "rbac.authorization.k8s.io", "rolebindings",
                null, null)).isEmpty());
        assertTrue(allowing(List.of(association("AmazonEKSAdminPolicy", cluster())), Request.resource("create",
                "team-a", "rbac.authorization.k8s.io", "rolebindings", null, null)).isPresent());
    }

    @Test
    void clusterAdminPolicyAllowsEverythingIncludingNonResourceUrls() {
        List<AssociatedAccessPolicy> admin = List.of(association("AmazonEKSClusterAdminPolicy", cluster()));
        assertTrue(allowing(admin, Request.resource("delete", "", "", "nodes", null, "node-1")).isPresent());
        assertTrue(allowing(admin, Request.resource("escalate", "", "rbac.authorization.k8s.io", "clusterroles",
                null, "x")).isPresent());
        assertTrue(allowing(admin, Request.nonResource("get", "/healthz")).isPresent());
    }

    @Test
    void namespaceScopeAppliesOnlyInMatchingNamespaces() {
        AccessScope scope = new AccessScope("namespace", List.of("dev-*", "staging"));
        List<AssociatedAccessPolicy> edit = List.of(association("AmazonEKSEditPolicy", scope));
        assertTrue(allowing(edit, pods("delete", "dev-team-a")).isPresent());
        assertTrue(allowing(edit, pods("delete", "staging")).isPresent());
        assertTrue(allowing(edit, pods("delete", "staging-2")).isEmpty());
        assertTrue(allowing(edit, pods("delete", "prod")).isEmpty());
        // Like a RoleBinding: a cluster-wide list, a cluster-scoped object or a non-resource URL is out of scope.
        assertTrue(allowing(edit, pods("list", "")).isEmpty());
        assertTrue(allowing(List.of(association("AmazonEKSClusterAdminPolicy", scope)),
                Request.resource("get", "", "", "nodes", null, "node-1")).isEmpty());
        assertTrue(allowing(List.of(association("AmazonEKSClusterAdminPolicy", scope)),
                Request.nonResource("get", "/healthz")).isEmpty());
        // A namespace's own object carries its name as its namespace, as Kubernetes reports it.
        assertTrue(allowing(edit, Request.resource("get", "staging", "", "namespaces", null, "staging")).isPresent());
    }

    @Test
    void namespacePatternsMatchWholeNamesWithStarAsWildcard() {
        assertTrue(EksAccessPolicyAuthorizer.namespaceMatches("dev-*", "dev-"));
        assertTrue(EksAccessPolicyAuthorizer.namespaceMatches("*-dev", "team-dev"));
        assertTrue(EksAccessPolicyAuthorizer.namespaceMatches("*", "anything"));
        assertFalse(EksAccessPolicyAuthorizer.namespaceMatches("dev", "dev-a"));
        // Regex characters in a pattern are literal.
        assertFalse(EksAccessPolicyAuthorizer.namespaceMatches("dev.a", "devxa"));
    }

    @Test
    void resourceNamesRestrictARule() {
        List<AssociatedAccessPolicy> argo = List.of(association("AmazonEKSArgoCDClusterPolicy", cluster()));
        assertTrue(allowing(argo, Request.resource("get", "argocd", "", "configmaps", null,
                "argocd-notifications-cm")).isPresent());
        assertTrue(allowing(argo, Request.resource("get", "argocd", "", "configmaps", null, "other")).isEmpty());
    }

    @Test
    void policiesWithoutDocumentedRulesAndUnknownPoliciesAllowNothing() {
        assertTrue(allowing(List.of(association("AmazonEKSAutoNodePolicy", cluster())), pods("get", "a")).isEmpty());
        assertTrue(allowing(List.of(new AssociatedAccessPolicy(
                "arn:aws:eks::aws:cluster-access-policy/NoSuchPolicy", cluster(), 0, 0)), pods("get", "a")).isEmpty());
        assertTrue(allowing(List.of(), pods("get", "a")).isEmpty());
    }

    @Test
    void severalPoliciesCombineAsAUnion() {
        List<AssociatedAccessPolicy> policies = List.of(
                association("AmazonEKSViewPolicy", cluster()),
                association("AmazonEKSEditPolicy", new AccessScope("namespace", List.of("team-a"))));
        assertEquals(Optional.of("AmazonEKSViewPolicy"), allowing(policies, pods("get", "team-b")));
        assertEquals(Optional.of("AmazonEKSEditPolicy"), allowing(policies, pods("delete", "team-a")));
        assertTrue(allowing(policies, pods("delete", "team-b")).isEmpty());
    }

    private Optional<String> allowing(List<AssociatedAccessPolicy> policies, Request request) {
        return authorizer.allowingPolicy(policies, request);
    }

    private static Request pods(String verb, String namespace) {
        return Request.resource(verb, namespace, "", "pods", null, null);
    }

    private static AccessScope cluster() {
        return new AccessScope("cluster", List.of());
    }

    private static AssociatedAccessPolicy association(String policy, AccessScope scope) {
        return new AssociatedAccessPolicy(EksAccessPolicyCatalog.arn("aws", policy), scope, 0, 0);
    }
}
