package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.api.SecurityPolicyService;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlatformSecurityWebFilterTest {
    @Test
    void allowsPublicRequestToProceed() {
        PlatformSecurityServletFilterTestSupport support = new PlatformSecurityServletFilterTestSupport();
        PlatformSecurityWebFilter filter = new PlatformSecurityWebFilter(support.adapter, support.contextResolver);

        AtomicBoolean chained = new AtomicBoolean(false);
        WebFilterChain chain = exchange -> {
            chained.set(true);
            return reactor.core.publisher.Mono.empty();
        };

        filter.filter(MockServerWebExchange.from(MockServerHttpRequest.get("/health").build()), chain).block();

        assertTrue(chained.get());
    }

    @Test
    void deniesProtectedRequestWithoutAuthentication() {
        PlatformSecurityServletFilterTestSupport support = new PlatformSecurityServletFilterTestSupport();
        PlatformSecurityWebFilter filter = new PlatformSecurityWebFilter(support.adapter, support.contextResolver);

        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/orders").build());
        filter.filter(exchange, ex -> reactor.core.publisher.Mono.empty()).block();

        assertEquals(401, exchange.getResponse().getStatusCode().value());
    }

    private static final class PlatformSecurityServletFilterTestSupport {
        private final SecurityIngressAdapter adapter;
        private final SecurityContextResolver contextResolver;

        private PlatformSecurityServletFilterTestSupport() {
            SecurityPolicyService policyService = (request, context) -> {
                String boundary = request.attributes().get("security.boundary");
                if ("PUBLIC".equalsIgnoreCase(boundary)) {
                    return SecurityVerdict.allow("auth", "public boundary");
                }
                return context.authenticated()
                        ? SecurityVerdict.allow("auth", "authenticated")
                        : SecurityVerdict.deny("auth", "authentication required");
            };
            this.adapter = new SecurityIngressAdapter(policyService, new PathPatternSecurityBoundaryResolver(
                    java.util.List.of("/health"),
                    java.util.List.of("/api/**"),
                    java.util.List.of("/admin/**"),
                    java.util.List.of("/internal/**")
            ));
            this.contextResolver = request -> new SecurityContext(
                    false,
                    null,
                    Set.of(),
                    Map.of()
            );
        }
    }
}
