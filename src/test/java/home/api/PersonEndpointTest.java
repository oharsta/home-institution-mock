package home.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import home.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static io.restassured.RestAssured.given;
import static org.apache.http.HttpStatus.SC_OK;
import static org.hamcrest.Matchers.equalTo;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class PersonEndpointTest extends AbstractIntegrationTest {

    @Test
    void persons() throws Exception {
        given()
                .when()
                .auth().oauth2(opaqueAccessToken())
                .get("/persons/1")
                .then()
                .statusCode(SC_OK)
                .body("mail", equalTo("vandamme.mcw@universiteitvanharderwijk.nl"));
    }

}