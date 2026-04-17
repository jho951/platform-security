package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.policy.SecurityBoundary;
import io.github.jho951.platform.security.policy.SecurityBoundaryType;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PlatformSecurityServletFilterTest {
    @Test
    void publishesAuditEventAndStoresDownstreamHeaders() throws Exception {
        List<String> policies = new ArrayList<>();
        SecurityIngressAdapter adapter = new SecurityIngressAdapter(
                (request, context) -> SecurityVerdict.allow("test-policy", "ok"),
                request -> new SecurityBoundary(SecurityBoundaryType.PUBLIC, List.of("/health"))
        );
        PlatformSecurityServletFilter filter = new PlatformSecurityServletFilter(
                adapter,
                request -> new SecurityContext(false, null, Set.of(), Map.of()),
                Clock.systemUTC(),
                new SecurityIngressRequestFactory(
                        new DefaultClientIpResolver(new io.github.jho951.platform.security.policy.PlatformSecurityProperties.IpGuardProperties()),
                        new SecurityIdentityScrubber()
                ),
                new SecurityDownstreamIdentityPropagator(),
                event -> policies.add(event.policy())
        );
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/health");
        request.setRemoteAddr("127.0.0.1");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertEquals(200, response.getStatus());
        assertEquals(List.of("test-policy"), policies);
        assertEquals("PUBLIC", ((Map<?, ?>) request.getAttribute(SecurityDownstreamIdentityPropagator.ATTR_DOWNSTREAM_HEADERS)).get("X-Security-Boundary"));
    }

    @Test
    void resolvesBoundaryBeforeSecurityContext() throws Exception {
        AtomicReference<String> boundarySeenByResolver = new AtomicReference<>();
        AtomicReference<String> tokenSeenByResolver = new AtomicReference<>();
        SecurityIngressAdapter adapter = new SecurityIngressAdapter(
                (request, context) -> context.authenticated()
                        ? SecurityVerdict.allow("auth", "authenticated")
                        : SecurityVerdict.deny("auth", "authentication required"),
                request -> new SecurityBoundary(SecurityBoundaryType.INTERNAL, List.of("/internal/**"))
        );
        PlatformSecurityServletFilter filter = new PlatformSecurityServletFilter(
                adapter,
                request -> {
                    boundarySeenByResolver.set(request.attributes().get("security.boundary"));
                    tokenSeenByResolver.set(request.attributes().get("auth.accessToken"));
                    return new SecurityContext(true, "internal-service", Set.of(), Map.of());
                },
                Clock.systemUTC(),
                new SecurityIngressRequestFactory(
                        new DefaultClientIpResolver(new io.github.jho951.platform.security.policy.PlatformSecurityProperties.IpGuardProperties()),
                        new SecurityIdentityScrubber()
                )
        );
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/internal/sync");
        request.setRemoteAddr("127.0.0.1");
        request.addHeader("Authorization", "Bearer internal-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertEquals(200, response.getStatus());
        assertEquals("INTERNAL", boundarySeenByResolver.get());
        assertEquals("internal-token", tokenSeenByResolver.get());
    }

    @Test
    void usesCustomFailureResponseWriter() throws Exception {
        SecurityIngressAdapter adapter = new SecurityIngressAdapter(
                (request, context) -> SecurityVerdict.deny("auth", "authentication required"),
                request -> new SecurityBoundary(SecurityBoundaryType.PROTECTED, List.of("/api/**"))
        );
        PlatformSecurityServletFilter filter = new PlatformSecurityServletFilter(
                adapter,
                request -> new SecurityContext(false, null, Set.of(), Map.of()),
                Clock.systemUTC(),
                new SecurityIngressRequestFactory(
                        new DefaultClientIpResolver(new io.github.jho951.platform.security.policy.PlatformSecurityProperties.IpGuardProperties()),
                        new SecurityIdentityScrubber()
                ),
                new SecurityDownstreamIdentityPropagator(),
                event -> {
                },
                (request, response, failure) -> {
                    response.setStatus(failure.status());
                    response.setContentType("application/json");
                    response.getWriter().write("{\"httpStatus\":"
                            + failure.status()
                            + ",\"success\":false,\"message\":\""
                            + failure.message()
                            + "\",\"code\":\""
                            + failure.code()
                            + "\",\"data\":null}");
                }
        );
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/orders");
        request.setRemoteAddr("127.0.0.1");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertEquals(401, response.getStatus());
        assertEquals(
                "{\"httpStatus\":401,\"success\":false,\"message\":\"authentication required\",\"code\":\"security.auth.required\",\"data\":null}",
                response.getContentAsString()
        );
    }
}
