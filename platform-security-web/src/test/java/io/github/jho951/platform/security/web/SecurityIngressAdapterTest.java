package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityPolicyService;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SecurityIngressAdapterTest {
    @Test
    void normalizesPathBeforeEvaluation() {
        RecordingSecurityPolicyService policyService = new RecordingSecurityPolicyService();
        SecurityIngressAdapter adapter = new SecurityIngressAdapter(policyService, new PathPatternSecurityBoundaryResolver());

        SecurityRequest request = new SecurityRequest(
                "user-1",
                "127.0.0.1",
                "api/v1",
                "read",
                Map.of(),
                Instant.parse("2026-01-01T00:00:00Z")
        );
        SecurityContext context = new SecurityContext(true, "user-1", Set.of("USER"), Map.of());

        adapter.evaluate(request, context);

        assertEquals("/api/v1", policyService.lastRequest.path());
    }

    @Test
    void convertsDeniedVerdictToFailureResponse() {
        SecurityIngressAdapter adapter = new SecurityIngressAdapter(
                (request, context) -> SecurityVerdict.deny("auth", "authentication required"),
                new PathPatternSecurityBoundaryResolver()
        );

        SecurityFailureResponse response = adapter.evaluateFailureResponse(
                new SecurityRequest(
                        "user-1",
                        "127.0.0.1",
                        "api/v1",
                        "read",
                        Map.of(),
                        Instant.parse("2026-01-01T00:00:00Z")
                ),
                new SecurityContext(false, null, Set.of(), Map.of())
        );

        assertEquals(401, response.status());
        assertEquals("security.auth.required", response.code());
    }

    @Test
    void evaluatesUsingContextResolver() {
        RecordingSecurityPolicyService policyService = new RecordingSecurityPolicyService();
        SecurityIngressAdapter adapter = new SecurityIngressAdapter(policyService, new PathPatternSecurityBoundaryResolver());

        SecurityVerdict verdict = adapter.evaluate(
                new SecurityRequest(
                        "user-1",
                        "127.0.0.1",
                        "api/v1",
                        "read",
                        Map.of(
                                "auth.authenticated", "true",
                                "auth.principal", "user-1",
                                "auth.roles", "USER"
                        ),
                        Instant.parse("2026-01-01T00:00:00Z")
                ),
                request -> new SecurityContext(true, request.subject(), Set.of("USER"), Map.of())
        );

        assertEquals("test", verdict.policy());
        assertEquals("/api/v1", policyService.lastRequest.path());
    }

    private static final class RecordingSecurityPolicyService implements SecurityPolicyService {
        private SecurityRequest lastRequest;

        @Override
        public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
            lastRequest = request;
            return SecurityVerdict.allow("test", "ok");
        }
    }
}
