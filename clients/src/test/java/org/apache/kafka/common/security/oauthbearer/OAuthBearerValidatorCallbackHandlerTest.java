/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.kafka.common.security.oauthbearer;

import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_ALLOW_UNVERIFIED_ISSUER;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_EXPECTED_AUDIENCE;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_EXPECTED_ISSUER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.apache.kafka.common.config.internals.BrokerSecurityConfigs.ALLOWED_SASL_OAUTHBEARER_URLS_CONFIG;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.io.File;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.security.auth.callback.Callback;
import org.apache.kafka.common.config.ConfigException;
import org.apache.kafka.common.config.SaslConfigs;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.apache.kafka.common.security.oauthbearer.internals.secured.AccessTokenBuilder;
import org.apache.kafka.common.security.oauthbearer.internals.secured.AccessTokenValidator;
import org.apache.kafka.common.security.oauthbearer.internals.secured.AccessTokenValidatorFactory;
import org.apache.kafka.common.security.oauthbearer.internals.secured.CloseableVerificationKeyResolver;
import org.apache.kafka.common.security.oauthbearer.internals.secured.OAuthBearerTest;
import org.apache.kafka.common.utils.Utils;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.junit.jupiter.api.Test;

public class OAuthBearerValidatorCallbackHandlerTest extends OAuthBearerTest {

    @Test
    public void testBasic() throws Exception {
        String expectedAudience = "a";
        List<String> allAudiences = Arrays.asList(expectedAudience, "b", "c");
        AccessTokenBuilder builder = new AccessTokenBuilder()
            .audience(expectedAudience)
            .jwk(createRsaJwk())
            .alg(AlgorithmIdentifiers.RSA_USING_SHA256);
        String accessToken = builder.build();

        Map<String, Object> overrides = new HashMap<>();
        overrides.put(SASL_OAUTHBEARER_EXPECTED_AUDIENCE, allAudiences);
        overrides.put(SASL_OAUTHBEARER_ALLOW_UNVERIFIED_ISSUER, true);
        Map<String, ?> configs = getSaslConfigs(overrides);
        OAuthBearerValidatorCallbackHandler handler = createHandler(configs, builder);

        try {
            OAuthBearerValidatorCallback callback = new OAuthBearerValidatorCallback(accessToken);
            handler.handle(new Callback[]{callback});

            assertNotNull(callback.token());
            OAuthBearerToken token = callback.token();
            assertEquals(accessToken, token.value());
            assertEquals(builder.subject(), token.principalName());
            assertEquals(builder.expirationSeconds() * 1000, token.lifetimeMs());
            assertEquals(builder.issuedAtSeconds() * 1000, token.startTimeMs());
        } finally {
            handler.close();
        }
    }

    @Test
    public void testInvalidAccessToken() throws Exception {
        // There aren't different error messages for the validation step, so these are all the
        // same :(
        String substring = "invalid_token";
        assertInvalidAccessTokenFails("this isn't valid", substring);
        assertInvalidAccessTokenFails("this.isn't.valid", substring);
        assertInvalidAccessTokenFails(createAccessKey("this", "isn't", "valid"), substring);
        assertInvalidAccessTokenFails(createAccessKey("{}", "{}", "{}"), substring);
    }

    private void assertInvalidAccessTokenFails(String accessToken, String expectedMessageSubstring) throws Exception {
        Map<String, Object> overrides = new HashMap<>();
        overrides.put(SASL_OAUTHBEARER_EXPECTED_AUDIENCE, Arrays.asList("a"));
        overrides.put(SASL_OAUTHBEARER_EXPECTED_ISSUER, "https://issuer.example.com");
        Map<String, ?> configs = getSaslConfigs(overrides);
        OAuthBearerValidatorCallbackHandler handler = createHandler(configs, new AccessTokenBuilder());

        try {
            OAuthBearerValidatorCallback callback = new OAuthBearerValidatorCallback(accessToken);
            handler.handle(new Callback[] {callback});

            assertNull(callback.token());
            String actualMessage = callback.errorStatus();
            assertNotNull(actualMessage);
            assertTrue(actualMessage.contains(expectedMessageSubstring), String.format("The error message \"%s\" didn't contain the expected substring \"%s\"", actualMessage, expectedMessageSubstring));
        } finally {
            handler.close();
        }
    }

    @Test
    public void testFailsToConfigureWhenExpectedAudienceMissing() {
        // The broker's JWKS validator must refuse to start, rather than accept tokens whose audience cannot be verified.
        Map<String, ?> configs = getSaslConfigs(SASL_OAUTHBEARER_EXPECTED_ISSUER, "https://issuer.example.com");
        ConfigException e = assertThrows(ConfigException.class, () -> createHandler(configs, new AccessTokenBuilder()));
        assertTrue(e.getMessage().contains(SASL_OAUTHBEARER_EXPECTED_AUDIENCE), e.getMessage());
    }

    @Test
    public void testFailsToConfigureWhenExpectedIssuerMissing() {
        // The broker's JWKS validator must refuse to start, rather than accept tokens whose issuer cannot be verified.
        Map<String, ?> configs = getSaslConfigs(SASL_OAUTHBEARER_EXPECTED_AUDIENCE, Arrays.asList("a"));
        ConfigException e = assertThrows(ConfigException.class, () -> createHandler(configs, new AccessTokenBuilder()));
        assertTrue(e.getMessage().contains(SASL_OAUTHBEARER_EXPECTED_ISSUER), e.getMessage());
    }

    @Test
    public void testOptOutsAllowUnverifiedIssuerAndAudience() throws Exception {
        // With both opt-outs (as String values, the way a broker passes keys its KafkaConfig does not define),
        // a token with any audience and no issuer is accepted.
        AccessTokenBuilder builder = new AccessTokenBuilder()
            .audience("some-other-service")
            .jwk(createRsaJwk())
            .alg(AlgorithmIdentifiers.RSA_USING_SHA256);
        String accessToken = builder.build();
        Map<String, Object> overrides = new HashMap<>();
        overrides.put("sasl.oauthbearer.allow.unverified.audience", "true");
        overrides.put(SASL_OAUTHBEARER_ALLOW_UNVERIFIED_ISSUER, "true");
        OAuthBearerValidatorCallbackHandler handler = createHandler(getSaslConfigs(overrides), builder);
        try {
            OAuthBearerValidatorCallback callback = new OAuthBearerValidatorCallback(accessToken);
            handler.handle(new Callback[]{callback});
            assertNotNull(callback.token(), callback.errorStatus());
        } finally {
            handler.close();
        }
    }

    @Test
    public void testRejectsAttackerIssuerViaCallbackHandlerWithJwksUrl() throws Exception {
        // Port of upstream DefaultJwtValidatorTest.testRejectsAttackerIssuerViaDefaultJwtValidatorWithJwksUrl: with a
        // JWKS URL configured and expected.issuer unset, an attacker-issued token must never be accepted.
        PublicJsonWebKey jwk = createRsaJwk();
        String accessToken = new AccessTokenBuilder()
            .jwk(jwk)
            .alg(AlgorithmIdentifiers.RSA_USING_SHA256)
            .addCustomClaim("iss", "https://evil.example/attacker")
            .build();
        String jwksJson = new JsonWebKeySet(jwk).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        File tmpDir = createTempDir("access-token");
        String fileUrl = createTempFile(tmpDir, "jwks-", ".json", jwksJson).toURI().toString();
        System.setProperty(ALLOWED_SASL_OAUTHBEARER_URLS_CONFIG, fileUrl);
        Map<String, Object> raw = new HashMap<>();
        raw.put(SaslConfigs.SASL_OAUTHBEARER_JWKS_ENDPOINT_URL, fileUrl);
        // expected.issuer intentionally omitted; expected.audience is set so the issuer check is the one that fails
        raw.put(SASL_OAUTHBEARER_EXPECTED_AUDIENCE, Collections.singletonList("kafka-cluster"));
        OAuthBearerValidatorCallbackHandler handler = new OAuthBearerValidatorCallbackHandler();
        try {
            configureHandler(handler, getSaslConfigs(raw), Collections.emptyMap());
            OAuthBearerValidatorCallback callback = new OAuthBearerValidatorCallback(accessToken);
            handler.handle(new Callback[]{callback});
            if (callback.token() != null)
                fail("INSECURE: an attacker-issuer token was accepted with jwks.endpoint.url set (expected.issuer unset)");
        } catch (ConfigException e) {
            // securely rejected at configuration time
            assertTrue(e.getMessage().contains(SASL_OAUTHBEARER_EXPECTED_ISSUER), e.getMessage());
        } finally {
            handler.close();
            System.clearProperty(ALLOWED_SASL_OAUTHBEARER_URLS_CONFIG);
        }
    }

    private OAuthBearerValidatorCallbackHandler createHandler(Map<String, ?> options,
        AccessTokenBuilder builder) {
        OAuthBearerValidatorCallbackHandler handler = new OAuthBearerValidatorCallbackHandler();
        CloseableVerificationKeyResolver verificationKeyResolver = (jws, nestingContext) ->
                builder.jwk().getPublicKey();
        AccessTokenValidator accessTokenValidator = AccessTokenValidatorFactory.create(options, verificationKeyResolver);
        handler.init(verificationKeyResolver, accessTokenValidator);
        return handler;
    }

    private String createAccessKey(String header, String payload, String signature) {
        Base64.Encoder enc = Base64.getEncoder();
        header = enc.encodeToString(Utils.utf8(header));
        payload = enc.encodeToString(Utils.utf8(payload));
        signature = enc.encodeToString(Utils.utf8(signature));
        return String.format("%s.%s.%s", header, payload, signature);
    }

}
