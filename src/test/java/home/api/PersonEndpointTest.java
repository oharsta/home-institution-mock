package home.api;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import home.WireMockExtension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.apache.http.HttpStatus.SC_OK;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.*;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;

class PersonEndpointTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    @RegisterExtension
    WireMockExtension mockServer = new WireMockExtension(8081);

    @Test
    void persons() throws NoSuchProviderException, NoSuchAlgorithmException {
        JWKSet jwkSet = new JWKSet(generateRsaKey("key_id"));
        stubFor(get(urlPathMatching("/certs")).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(jwkSet.toJSONObject().toString())));
        String accessToken = //TODO
                String jti = UUID.randomUUID().toString();

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .audience(audiences)
                .expirationTime(Date.from(clock.instant().plus(tokenValidity, ChronoUnit.SECONDS)))
                .jwtID(jti)
                .issuer(issuer)
                .issueTime(Date.from(clock.instant()))
                .subject(optionalUser.map(User::getSub).orElse(client.getClientId()))
                .notBeforeTime(new Date(System.currentTimeMillis()));
        given()
                .when()
                .auth().oauth2()
                .get("/persons/1")
                .then()
                .statusCode(SC_OK)
                .body("status", equalTo("UP"));


    }

    private RSAKey generateRsaKey(String keyID) throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .algorithm(JWSAlgorithm.RS256)
                .keyID(keyID)
                .build();
    }

}