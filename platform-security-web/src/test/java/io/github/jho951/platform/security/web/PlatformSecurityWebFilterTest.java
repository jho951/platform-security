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
import java.util.concurrent.atomic.AtomicReference;

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

    @Test
    void usesCustomReactiveFailureResponseWriter() {
        PlatformSecurityServletFilterTestSupport support = new PlatformSecurityServletFilterTestSupport();
        PlatformSecurityWebFilter filter = new PlatformSecurityWebFilter(
                support.adapter,
                support.contextResolver,
                java.time.Clock.systemUTC(),
                new SecurityIngressRequestFactory(
                        new DefaultClientIpResolver(new io.github.jho951.platform.security.policy.PlatformSecurityProperties.IpGuardProperties()),
                        new SecurityIdentityScrubber()
                ),
                new SecurityDownstreamIdentityPropagator(),
                event -> {
                },
                (exchange, failure) -> {
                    exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.valueOf(failure.status()));
                    byte[] body = ("{\"httpStatus\":"
                            + failure.status()
                            + ",\"success\":false,\"message\":\""
                            + failure.message()
                            + "\",\"code\":\""
                            + failure.code()
                            + "\",\"data\":null}")
                            .getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    return exchange.getResponse()
                            .writeWith(reactor.core.publisher.Mono.just(exchange.getResponse().bufferFactory().wrap(body)));
                }
        );

        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/orders").build());
        filter.filter(exchange, ex -> reactor.core.publisher.Mono.empty()).block();

        assertEquals(401, exchange.getResponse().getStatusCode().value());
        assertEquals(
                "{\"httpStatus\":401,\"success\":false,\"message\":\"authentication required\",\"code\":\"security.auth.required\",\"data\":null}",
                exchange.getResponse().getBodyAsString().block()
        );
    }

    @Test
    void resolvesBoundaryBeforeSecurityContext() {
        AtomicReference<String> boundarySeenByResolver = new AtomicReference<>();
        AtomicReference<String> tokenSeenByResolver = new AtomicReference<>();
        SecurityPolicyService policyService = (request, context) -> context.authenticated()
                ? SecurityVerdict.allow("auth", "authenticated")
                : SecurityVerdict.deny("auth", "authentication required");
        SecurityIngressAdapter adapter = new SecurityIngressAdapter(
                policyService,
                new PathPatternSecurityBoundaryResolver(
                        java.util.List.of("/health"),
                        java.util.List.of("/api/**"),
                        java.util.List.of("/admin/**"),
                        java.util.List.of("/internal/**")
                )
        );
        PlatformSecurityWebFilter filter = new PlatformSecurityWebFilter(
                adapter,
                request -> {
                    boundarySeenByResolver.set(request.attributes().get("security.boundary"));
                    tokenSeenByResolver.set(request.attributes().get("auth.accessToken"));
                    return new SecurityContext(true, "internal-service", Set.of(), Map.of());
                }
        );

        AtomicBoolean chained = new AtomicBoolean(false);
        WebFilterChain chain = exchange -> {
            chained.set(true);
            return reactor.core.publisher.Mono.empty();
        };
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/internal/sync")
                        .header("Authorization", "Bearer internal-token")
                        .build()
        );

        filter.filter(exchange, chain).block();

        assertTrue(chained.get());
        assertEquals("INTERNAL", boundarySeenByResolver.get());
        assertEquals("internal-token", tokenSeenByResolver.get());
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
