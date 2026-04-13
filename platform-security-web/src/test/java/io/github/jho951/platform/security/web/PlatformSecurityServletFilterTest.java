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
                result -> policies.add(result.verdict().policy())
        );
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/health");
        request.setRemoteAddr("127.0.0.1");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertEquals(200, response.getStatus());
        assertEquals(List.of("test-policy"), policies);
        assertEquals("PUBLIC", ((Map<?, ?>) request.getAttribute(SecurityDownstreamIdentityPropagator.ATTR_DOWNSTREAM_HEADERS)).get("X-Security-Boundary"));
    }
}
