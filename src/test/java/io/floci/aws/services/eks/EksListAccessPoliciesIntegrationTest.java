package io.floci.aws.services.eks;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * ListAccessPolicies lists the access policies EKS lists, vendored in {@code eks/access-policies.json}: in name
 * order, a page at a time, each ARN in the caller's partition, and refuses a bad page size or token as EKS does.
 */
@QuarkusTest
class EksListAccessPoliciesIntegrationTest {

    private static final String ACCOUNT = "135791357913";
    private static final String REGION = "us-east-1";
    private static List<String> vendored;

    @BeforeAll
    static void readTheVendoredPolicies() throws Exception {
        List<String> names = new ArrayList<>();
        try (InputStream catalog = EksListAccessPoliciesIntegrationTest.class
                .getResourceAsStream("/eks/access-policies.json")) {
            new ObjectMapper().readTree(catalog).path("accessPolicies")
                    .forEach(policy -> names.add(policy.path("name").asText()));
        }
        vendored = List.copyOf(names);
    }

    @Test
    void everyPolicyIsListedInNameOrderWithItsArnAndNoToken() {
        JsonPath listed = given().header("Authorization", auth(ACCOUNT, REGION, "eks"))
                .when().get("/access-policies")
                .then().statusCode(200).body("nextToken", nullValue())
                .extract().jsonPath();

        assertEquals(vendored, listed.getList("accessPolicies.name", String.class));
        assertEquals(vendored.stream().map(name -> "arn:aws:eks::aws:cluster-access-policy/" + name).toList(),
                listed.getList("accessPolicies.arn", String.class));
    }

    @Test
    void eachPageOfTenIsTheNextTenAndOnlyTheLastHasNoToken() {
        String token = null;
        int from = 0;
        do {
            JsonPath page = given().header("Authorization", auth(ACCOUNT, REGION, "eks"))
                    .queryParam("maxResults", 10)
                    .queryParams(token == null ? Map.of() : Map.of("nextToken", token))
                    .when().get("/access-policies")
                    .then().statusCode(200)
                    .extract().jsonPath();
            int to = Math.min(from + 10, vendored.size());
            assertEquals(vendored.subList(from, to), page.getList("accessPolicies.name", String.class));
            token = page.getString("nextToken");
            assertEquals(to < vendored.size(), token != null);
            from = to;
        } while (token != null);
        assertEquals(vendored.size(), from);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 101})
    void aMaxResultsOutsideOneToOneHundredIsRefusedAsEksRefusesIt(int maxResults) {
        given().header("Authorization", auth(ACCOUNT, REGION, "eks"))
                .queryParam("maxResults", maxResults)
                .when().get("/access-policies")
                .then().statusCode(400)
                .body("__type", equalTo("InvalidParameterException"))
                .body("message", equalTo("maxResults must be a number between 1 and 100."));
    }

    @Test
    void anUnreadableTokenIsRefusedAsEksRefusesIt() {
        given().header("Authorization", auth(ACCOUNT, REGION, "eks"))
                .queryParam("nextToken", "not-a-token")
                .when().get("/access-policies")
                .then().statusCode(400)
                .body("__type", equalTo("InvalidParameterException"))
                .body("message", equalTo("The specified nextToken is invalid: unrecognized format."));
    }

    @Test
    void anArnIsInTheCallersPartition() {
        given().header("Authorization", auth(ACCOUNT, "cn-north-1", "eks"))
                .when().get("/access-policies")
                .then().statusCode(200)
                .body("accessPolicies.find { it.name == 'AmazonEKSViewPolicy' }.arn",
                        equalTo("arn:aws-cn:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"));
    }
}
