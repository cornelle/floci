package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.testing.PartitionCleanup;
import io.github.hectorvent.floci.testing.PartitionMatrix;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.List;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Behaviour that AWS gates on the partition rather than on a literal region: a WAF CLOUDFRONT
 * scope exists only where CloudFront does and lives in the partition's implicit global region,
 * and Lightsail exists only in the commercial partition.
 */
@QuarkusTest
class PartitionRegionGatesIntegrationTest {

    private static final String JSON_1_1 = "application/x-amz-json-1.1";

    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    private static Response createIpSet(String region, String name) {
        return given()
            .header("Authorization", PartitionMatrix.sigV4Auth(region, "wafv2"))
            .header("X-Amz-Target", "AWSWAF_20190729.CreateIPSet")
            .contentType(JSON_1_1)
            .body("{\"Name\":\"" + name + "\",\"Scope\":\"CLOUDFRONT\",\"IPAddressVersion\":\"IPV4\",\"Addresses\":[\"10.0.0.0/8\"]}")
        .when().post("/");
    }

    @Test
    void cloudFrontScopeIsRejectedWhereThePartitionHasNoCloudFront() {
        createIpSet("us-gov-west-1", "gov-" + Long.toString(System.nanoTime(), 36)).then().statusCode(400)
                .body("__type", containsString("WAFInvalidParameterException"))
                .body("Reason", containsString("aws-us-gov"));
    }

    /** The scope is unavailable for every operation in such a partition, not only for creates. */
    @Test
    void cloudFrontScopeListsAreRejectedWhereThePartitionHasNoCloudFront() {
        for (String action : new String[] {"ListIPSets", "ListWebACLs"}) {
            given()
                .header("Authorization", PartitionMatrix.sigV4Auth("us-gov-west-1", "wafv2"))
                .header("X-Amz-Target", "AWSWAF_20190729." + action)
                .contentType(JSON_1_1)
                .body("{\"Scope\":\"CLOUDFRONT\"}")
            .when().post("/")
            .then().statusCode(400)
                .body("__type", containsString("WAFInvalidParameterException"))
                .body("Reason", containsString("aws-us-gov"));
        }
    }

    private static Response createPrefixList(String region, String name) {
        return given()
            .header("Authorization", PartitionMatrix.sigV4Auth(region, "ec2"))
            .formParam("Action", "CreateManagedPrefixList")
            .formParam("Version", "2016-11-15")
            .formParam("PrefixListName", name)
            .formParam("AddressFamily", "IPv4")
            .formParam("MaxEntries", "5")
        .when().post("/");
    }

    /**
     * China's AWS-managed lists are named {@code cn.com.amazonaws.<region>.<service>}, so a
     * customer list may not take that prefix there; elsewhere the prefix is nothing special.
     */
    @Test
    void theChinaManagedPrefixListNameIsReservedOnlyInChina() {
        createPrefixList("cn-north-1", "cn.com.amazonaws.cn-north-1.s3").then().statusCode(400)
            .body(containsString("InvalidParameterValue"))
            .body(containsString("cn.com.amazonaws."));

        String name = "cn.com.amazonaws.custom-" + Long.toString(System.nanoTime(), 36);
        Response created = createPrefixList("us-east-1", name);
        created.then().statusCode(200);
        String id = created.xmlPath().getString("CreateManagedPrefixListResponse.prefixList.prefixListId");
        cleanup.register(() -> given()
            .header("Authorization", PartitionMatrix.sigV4Auth("us-east-1", "ec2"))
            .formParam("Action", "DeleteManagedPrefixList")
            .formParam("Version", "2016-11-15")
            .formParam("PrefixListId", id)
        .when().post("/"));
    }

    /** An edge-optimized domain is fronted by CloudFront; a regional one needs nothing from it. */
    @Test
    void edgeCustomDomainsAreRejectedWhereThePartitionHasNoCloudFront() {
        String suffix = Long.toString(System.nanoTime(), 36);
        given()
            .header("Authorization", PartitionMatrix.sigV4Auth("us-gov-west-1", "apigateway"))
            .contentType("application/json")
            .body("{\"domainName\":\"edge-" + suffix + ".example.com\","
                    + "\"certificateArn\":\"arn:aws-us-gov:acm:us-gov-west-1:000000000000:certificate/edge\","
                    + "\"endpointConfiguration\":{\"types\":[\"EDGE\"]}}")
        .when().post("/domainnames")
        .then().statusCode(400)
            .body(containsString("not available in partition aws-us-gov"));

        String regional = "regional-" + suffix + ".example.com";
        given()
            .header("Authorization", PartitionMatrix.sigV4Auth("us-gov-west-1", "apigateway"))
            .contentType("application/json")
            .body("{\"domainName\":\"" + regional + "\","
                    + "\"regionalCertificateArn\":\"arn:aws-us-gov:acm:us-gov-west-1:000000000000:certificate/regional\","
                    + "\"endpointConfiguration\":{\"types\":[\"REGIONAL\"]}}")
        .when().post("/domainnames")
        .then().statusCode(201);
        cleanup.register(() -> given()
            .header("Authorization", PartitionMatrix.sigV4Auth("us-gov-west-1", "apigateway"))
        .when().delete("/domainnames/" + regional));
    }

    @Test
    void cloudFrontScopeLivesInThePartitionsImplicitGlobalRegion() {
        String name = "cn-" + Long.toString(System.nanoTime(), 36);
        Response created = createIpSet("cn-north-1", name);
        created.then().statusCode(200);
        String arn = created.jsonPath().getString("Summary.ARN");
        String id = created.jsonPath().getString("Summary.Id");
        String lockToken = created.jsonPath().getString("Summary.LockToken");
        cleanup.register(() -> given()
            .header("Authorization", PartitionMatrix.sigV4Auth("cn-north-1", "wafv2"))
            .header("X-Amz-Target", "AWSWAF_20190729.DeleteIPSet")
            .contentType(JSON_1_1)
            .body("{\"Name\":\"" + name + "\",\"Scope\":\"CLOUDFRONT\",\"Id\":\"" + id + "\",\"LockToken\":\"" + lockToken + "\"}")
        .when().post("/"));
        assertTrue(arn.startsWith("arn:aws-cn:wafv2:cn-northwest-1:000000000000:global/ipset/" + name + "/"), arn);
    }

    /** The AWS-owned gateway prefix lists carry the China service-name prefix for S3, but not for DynamoDB. */
    @Test
    void managedPrefixListsUseThePartitionsVpcEndpointServiceNames() {
        List<String> names = given()
            .header("Authorization", PartitionMatrix.sigV4Auth("cn-north-1", "ec2"))
            .formParam("Action", "DescribeManagedPrefixLists")
            .formParam("Version", "2016-11-15")
        .when().post("/").then().statusCode(200)
            .extract().xmlPath().getList("DescribeManagedPrefixListsResponse.prefixListSet.item.prefixListName");
        assertTrue(names.contains("cn.com.amazonaws.cn-north-1.s3"), names.toString());
        assertTrue(names.contains("com.amazonaws.cn-north-1.dynamodb"), names.toString());
    }

    @Test
    void lightsailRegionsAreEmptyOutsideTheCommercialPartition() {
        given()
            .header("Authorization", PartitionMatrix.sigV4Auth("cn-north-1", "lightsail"))
            .header("X-Amz-Target", "Lightsail_20161128.GetRegions")
            .contentType(JSON_1_1)
            .body("{}")
        .when().post("/").then().statusCode(200)
            .body("regions", hasSize(0));
        given()
            .header("Authorization", PartitionMatrix.sigV4Auth("us-east-1", "lightsail"))
            .header("X-Amz-Target", "Lightsail_20161128.GetRegions")
            .contentType(JSON_1_1)
            .body("{}")
        .when().post("/").then().statusCode(200)
            .body("regions", hasSize(4));
    }
}
