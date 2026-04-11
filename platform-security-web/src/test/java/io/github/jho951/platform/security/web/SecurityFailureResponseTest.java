package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityVerdict;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SecurityFailureResponseTest {
    @Test
    void mapsAuthDenialToUnauthorized() {
        SecurityFailureResponse response = SecurityFailureResponse.from(SecurityVerdict.deny("auth", "authentication required"));

        assertEquals(401, response.status());
        assertEquals("security.auth.required", response.code());
        assertEquals("authentication required", response.message());
    }

    @Test
    void mapsRateLimitDenialToTooManyRequests() {
        SecurityFailureResponse response = SecurityFailureResponse.from(SecurityVerdict.deny("rate-limiter", "rate limit exceeded"));

        assertEquals(429, response.status());
        assertEquals("security.rate_limited", response.code());
        assertEquals("rate limit exceeded", response.message());
    }

    @Test
    void mapsUnknownDenialToForbidden() {
        SecurityFailureResponse response = SecurityFailureResponse.from(SecurityVerdict.deny("custom", "blocked"));

        assertEquals(403, response.status());
        assertEquals("security.denied", response.code());
        assertEquals("blocked", response.message());
    }

    @Test
    void keepsAllowedVerdictAsGenericSuccessResponse() {
        SecurityFailureResponse response = SecurityFailureResponse.from(SecurityVerdict.allow("auth", "authenticated"));

        assertEquals(200, response.status());
        assertEquals("security.allowed", response.code());
        assertEquals("authenticated", response.message());
    }
}
