package io.floci.aws.services.eks;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.enterprise.context.ApplicationScoped;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The EKS access policies AWS defines, with the Kubernetes rules each grants, from
 * {@code eks/access-policies.json} (copied from the EKS User Guide's "Review access policy permissions").
 * A policy whose rules AWS describes only in prose is listed but carries no rules, so it grants nothing.
 */
@ApplicationScoped
public class EksAccessPolicyCatalog {

    static final String RESOURCE = "eks/access-policies.json";
    private static final String ARN_RESOURCE_PREFIX = "cluster-access-policy/";

    private final Map<String, Policy> policies;
    private final List<String> names;

    public EksAccessPolicyCatalog() {
        this(load());
    }

    EksAccessPolicyCatalog(List<Policy> policies) {
        Map<String, Policy> byName = new LinkedHashMap<>();
        for (Policy policy : policies) {
            byName.put(policy.name(), policy);
        }
        this.policies = Map.copyOf(byName);
        this.names = policies.stream().map(Policy::name).toList();
    }

    @RegisterForReflection
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Rule(List<String> apiGroups, List<String> resources, List<String> verbs,
                       List<String> resourceNames, List<String> nonResourceURLs) {
        public Rule {
            apiGroups = apiGroups == null ? List.of() : List.copyOf(apiGroups);
            resources = resources == null ? List.of() : List.copyOf(resources);
            verbs = verbs == null ? List.of() : List.copyOf(verbs);
            resourceNames = resourceNames == null ? List.of() : List.copyOf(resourceNames);
            nonResourceURLs = nonResourceURLs == null ? List.of() : List.copyOf(nonResourceURLs);
        }
    }

    /** {@code rules} is empty for a policy AWS publishes no rule table for. */
    @RegisterForReflection
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Policy(String name, List<Rule> rules) {
        public Policy {
            rules = rules == null ? List.of() : List.copyOf(rules);
        }
    }

    @RegisterForReflection
    @JsonIgnoreProperties(ignoreUnknown = true)
    record CatalogFile(List<Policy> policies) {}

    private static List<Policy> load() {
        try (InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("EKS access policy catalog " + RESOURCE + " is missing");
            }
            CatalogFile file = new ObjectMapper().readValue(in, CatalogFile.class);
            return file.policies() == null ? List.of() : file.policies();
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read the EKS access policy catalog " + RESOURCE, e);
        }
    }

    /** Every policy name, in the order AWS documents them. */
    public List<String> names() {
        return names;
    }

    public Optional<Policy> find(String name) {
        return Optional.ofNullable(name == null ? null : policies.get(name));
    }

    /** The policy an access policy ARN names, or empty when the ARN names none AWS defines. */
    public Optional<Policy> forArn(String policyArn) {
        if (policyArn == null) {
            return Optional.empty();
        }
        int at = policyArn.lastIndexOf(ARN_RESOURCE_PREFIX);
        return at < 0 ? Optional.empty() : find(policyArn.substring(at + ARN_RESOURCE_PREFIX.length()));
    }

    /** {@code arn:<partition>:eks::aws:cluster-access-policy/<name>}, as AWS names its access policies. */
    public static String arn(String partition, String name) {
        return "arn:" + partition + ":eks::aws:" + ARN_RESOURCE_PREFIX + name; // partition-literal: the AWS-managed account
    }
}
