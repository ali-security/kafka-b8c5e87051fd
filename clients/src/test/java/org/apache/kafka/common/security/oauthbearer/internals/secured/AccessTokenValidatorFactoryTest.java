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

package org.apache.kafka.common.security.oauthbearer.internals.secured;

import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_ALLOW_UNVERIFIED_AUDIENCE;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_ALLOW_UNVERIFIED_ISSUER;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_EXPECTED_AUDIENCE;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_EXPECTED_ISSUER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.config.ConfigException;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginCallbackHandler;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.utils.LogCaptureAppender;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.junit.jupiter.api.Test;

public class AccessTokenValidatorFactoryTest extends OAuthBearerTest {

    @Test
    public void testConfigureThrowsExceptionOnAccessTokenValidatorInit() {
        OAuthBearerLoginCallbackHandler handler = new OAuthBearerLoginCallbackHandler();
        AccessTokenRetriever accessTokenRetriever = new AccessTokenRetriever() {
            @Override
            public void init() throws IOException {
                throw new IOException("My init had an error!");
            }
            @Override
            public String retrieve() {
                return "dummy";
            }
        };

        Map<String, ?> configs = getSaslConfigs();
        AccessTokenValidator accessTokenValidator = AccessTokenValidatorFactory.create(configs);

        assertThrowsWithMessage(
            KafkaException.class, () -> handler.init(accessTokenRetriever, accessTokenValidator), "encountered an error when initializing");
    }

    @Test
    public void testConfigureThrowsExceptionOnAccessTokenValidatorClose() {
        OAuthBearerLoginCallbackHandler handler = new OAuthBearerLoginCallbackHandler();
        AccessTokenRetriever accessTokenRetriever = new AccessTokenRetriever() {
            @Override
            public void close() throws IOException {
                throw new IOException("My close had an error!");
            }
            @Override
            public String retrieve() {
                return "dummy";
            }
        };

        Map<String, ?> configs = getSaslConfigs();
        AccessTokenValidator accessTokenValidator = AccessTokenValidatorFactory.create(configs);
        handler.init(accessTokenRetriever, accessTokenValidator);

        // Basically asserting this doesn't throw an exception :(
        handler.close();
    }

    // Ports of upstream 9c7fad33's BrokerJwtValidatorTest cases. In 3.7.1 the broker's JWKS validator is built by
    // AccessTokenValidatorFactory.create(configs, saslMechanism, resolver), which is where the fail-fast lives.

    private static final String ATTACKER_ISSUER = "https://evil.example/";

    private static final String EXPECTED_ISSUER = "https://legit.example/";

    private static final String ATTACKER_AUDIENCE = "https://evil.example/other-service";

    private static final String EXPECTED_AUDIENCE = "https://legit.example/other-service";

    private static AccessTokenValidator brokerValidator(PublicJsonWebKey jwk, Map<String, ?> configs) {
        CloseableVerificationKeyResolver resolver = (jws, nestingContext) -> jwk.getKey();
        return AccessTokenValidatorFactory.create(configs, resolver);
    }

    private Map<String, ?> configs(Object... keysAndValues) {
        Map<String, Object> raw = new HashMap<>();
        for (int i = 0; i < keysAndValues.length; i += 2)
            raw.put((String) keysAndValues[i], keysAndValues[i + 1]);
        return getSaslConfigs(raw);
    }

    @Test
    public void testRejectMissingIssuerClaimWhenExpectedIssuerSet() throws Exception {
        PublicJsonWebKey jwk = createRsaJwk();
        String accessToken = new AccessTokenBuilder()
            .jwk(jwk)
            .alg(AlgorithmIdentifiers.RSA_USING_SHA256)
            .audience(EXPECTED_AUDIENCE)   // valid audience, but no iss claim is set
            .build();
        AccessTokenValidator validator = brokerValidator(jwk, configs(
            SASL_OAUTHBEARER_EXPECTED_ISSUER, EXPECTED_ISSUER,
            SASL_OAUTHBEARER_EXPECTED_AUDIENCE, Collections.singletonList(EXPECTED_AUDIENCE)));

        // With an expected issuer configured, jose4j requires the "iss" claim to be present.
        ValidateException e = assertThrows(ValidateException.class, () -> validator.validate(accessToken));
        assertErrorMessageContains(e.getMessage(), EXPECTED_ISSUER);
    }

    @Test
    public void testConfigureFailsWhenExpectedIssuerUnset() throws Exception {
        PublicJsonWebKey jwk = createRsaJwk();
        assertThrowsWithMessage(ConfigException.class,
            () -> brokerValidator(jwk, configs(SASL_OAUTHBEARER_EXPECTED_AUDIENCE, Collections.singletonList(EXPECTED_AUDIENCE))),
            SASL_OAUTHBEARER_EXPECTED_ISSUER);
    }

    @Test
    public void testExpectedIssuerSet() throws Exception {
        PublicJsonWebKey jwk = createRsaJwk();
        String accessToken = new AccessTokenBuilder()
            .jwk(jwk)
            .alg(AlgorithmIdentifiers.RSA_USING_SHA256)
            .addCustomClaim("iss", ATTACKER_ISSUER)
            .audience(EXPECTED_AUDIENCE)
            .build();
        AccessTokenValidator validator = brokerValidator(jwk, configs(
            SASL_OAUTHBEARER_EXPECTED_ISSUER, EXPECTED_ISSUER,
            SASL_OAUTHBEARER_EXPECTED_AUDIENCE, Collections.singletonList(EXPECTED_AUDIENCE)));

        ValidateException e = assertThrows(ValidateException.class, () -> validator.validate(accessToken));
        // jose4j reports the issuer mismatch; the message includes the offending issuer value
        assertErrorMessageContains(e.getMessage(), ATTACKER_ISSUER);
    }

    @Test
    public void testConfigureFailsWhenExpectedAudienceUnset() throws Exception {
        PublicJsonWebKey jwk = createRsaJwk();
        assertThrowsWithMessage(ConfigException.class,
            () -> brokerValidator(jwk, configs(SASL_OAUTHBEARER_EXPECTED_ISSUER, EXPECTED_ISSUER)),
            SASL_OAUTHBEARER_EXPECTED_AUDIENCE);
    }

    @Test
    public void testRejectWrongAudienceWhenExpectedAudienceSet() throws Exception {
        PublicJsonWebKey jwk = createRsaJwk();
        String accessToken = new AccessTokenBuilder()
            .jwk(jwk)
            .alg(AlgorithmIdentifiers.RSA_USING_SHA256)
            .addCustomClaim("iss", EXPECTED_ISSUER)
            .audience(ATTACKER_AUDIENCE)
            .build();
        AccessTokenValidator validator = brokerValidator(jwk, configs(
            SASL_OAUTHBEARER_EXPECTED_ISSUER, EXPECTED_ISSUER,
            SASL_OAUTHBEARER_EXPECTED_AUDIENCE, Collections.singletonList(EXPECTED_AUDIENCE)));

        ValidateException e = assertThrows(ValidateException.class, () -> validator.validate(accessToken));
        // jose4j reports the audience mismatch; the message includes the offending audience value
        assertErrorMessageContains(e.getMessage(), ATTACKER_AUDIENCE);
    }

    @Test
    public void testAllowUnverifiedAudience() throws Exception {
        PublicJsonWebKey jwk = createRsaJwk();
        AccessTokenBuilder builder = new AccessTokenBuilder()
            .jwk(jwk)
            .alg(AlgorithmIdentifiers.RSA_USING_SHA256)
            .addCustomClaim("iss", EXPECTED_ISSUER)
            .audience(ATTACKER_AUDIENCE);   // an audience that matches no expected audience
        String accessToken = builder.build();
        AccessTokenValidator validator = brokerValidator(jwk, configs(
            SASL_OAUTHBEARER_EXPECTED_ISSUER, EXPECTED_ISSUER,
            SASL_OAUTHBEARER_ALLOW_UNVERIFIED_AUDIENCE, true));

        OAuthBearerToken token = validator.validate(accessToken);
        assertEquals(builder.subject(), token.principalName());
    }

    @Test
    public void testAllowUnverifiedIssuer() throws Exception {
        PublicJsonWebKey jwk = createRsaJwk();
        AccessTokenBuilder builder = new AccessTokenBuilder()
            .jwk(jwk)
            .alg(AlgorithmIdentifiers.RSA_USING_SHA256)
            .addCustomClaim("iss", ATTACKER_ISSUER)   // an issuer that matches no expected issuer
            .audience(EXPECTED_AUDIENCE);
        String accessToken = builder.build();
        AccessTokenValidator validator = brokerValidator(jwk, configs(
            SASL_OAUTHBEARER_EXPECTED_AUDIENCE, Collections.singletonList(EXPECTED_AUDIENCE),
            SASL_OAUTHBEARER_ALLOW_UNVERIFIED_ISSUER, true));

        OAuthBearerToken token = validator.validate(accessToken);
        assertEquals(builder.subject(), token.principalName());
    }

    @Test
    public void testAllowUnverifiedIssuerAndAudience() throws Exception {
        PublicJsonWebKey jwk = createRsaJwk();
        AccessTokenBuilder builder = new AccessTokenBuilder()
            .jwk(jwk)
            .alg(AlgorithmIdentifiers.RSA_USING_SHA256)
            .addCustomClaim("iss", ATTACKER_ISSUER)   // neither the issuer nor the audience matches anything expected
            .audience(ATTACKER_AUDIENCE);
        String accessToken = builder.build();
        // Neither expected.issuer nor expected.audience is set; both opt-outs are enabled so configuration succeeds.
        Map<String, ?> saslConfigs = configs(
            SASL_OAUTHBEARER_ALLOW_UNVERIFIED_ISSUER, true,
            SASL_OAUTHBEARER_ALLOW_UNVERIFIED_AUDIENCE, true);

        AccessTokenValidator validator;
        try (LogCaptureAppender appender = LogCaptureAppender.createAndRegister(AccessTokenValidatorFactory.class)) {
            appender.setClassLoggerToDebug(AccessTokenValidatorFactory.class);
            validator = brokerValidator(jwk, saslConfigs);
            // Each opt-out path must log a WARN naming the config that disabled the check.
            List<String> warnings = appender.getEvents().stream()
                .filter(event -> "WARN".equals(event.getLevel()))
                .map(LogCaptureAppender.Event::getMessage)
                .collect(Collectors.toList());
            assertTrue(warnings.stream().anyMatch(m -> m.contains(SASL_OAUTHBEARER_ALLOW_UNVERIFIED_ISSUER)),
                "Expected a WARN mentioning " + SASL_OAUTHBEARER_ALLOW_UNVERIFIED_ISSUER + ", got " + warnings);
            assertTrue(warnings.stream().anyMatch(m -> m.contains(SASL_OAUTHBEARER_ALLOW_UNVERIFIED_AUDIENCE)),
                "Expected a WARN mentioning " + SASL_OAUTHBEARER_ALLOW_UNVERIFIED_AUDIENCE + ", got " + warnings);
        }

        // With both opt-outs in effect, a token whose issuer and audience match nothing configured is still accepted.
        OAuthBearerToken token = validator.validate(accessToken);
        assertEquals(builder.subject(), token.principalName());
    }

    @Test
    public void testConfigureFailsWhenNeitherExpectedSet() throws Exception {
        PublicJsonWebKey jwk = createRsaJwk();
        // With neither expected value set and no opt-out, configuration must fail fast. The audience guard runs
        // first, so its message is the one that surfaces.
        assertThrowsWithMessage(ConfigException.class,
            () -> brokerValidator(jwk, getSaslConfigs()),
            SASL_OAUTHBEARER_EXPECTED_AUDIENCE);
    }

}
