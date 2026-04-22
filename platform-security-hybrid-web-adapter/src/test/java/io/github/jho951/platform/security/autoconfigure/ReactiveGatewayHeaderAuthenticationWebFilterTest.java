package io.github.jho951.platform.security.autoconfigure;

import io.github.jho951.platform.security.api.GatewayUserPrincipal;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;

import java.security.Principal;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;

class ReactiveGatewayHeaderAuthenticationWebFilterTest {

    @Test
    void injectsGatewayPrincipalIntoReactiveExchangeWhenHeaderModeIsEnabled() {
        PlatformSecurityProperties.GatewayHeaderProperties properties = new PlatformSecurityProperties.GatewayHeaderProperties();
        properties.setEnabled(true);
        ReactiveGatewayHeaderAuthenticationWebFilter filter = new ReactiveGatewayHeaderAuthenticationWebFilter(properties);
        UUID userId = UUID.randomUUID();
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/orders")
                        .header(properties.getUserIdHeader(), userId.toString())
                        .header(properties.getUserStatusHeader(), "A")
                        .build()
        );
        AtomicReference<Principal> principalSeenByChain = new AtomicReference<>();
        WebFilterChain chain = webExchange -> webExchange.getPrincipal()
                .doOnNext(principalSeenByChain::set)
                .then();

        filter.filter(exchange, chain).block();

        assertInstanceOf(GatewayUserPrincipal.class, principalSeenByChain.get());
        GatewayUserPrincipal principal = (GatewayUserPrincipal) principalSeenByChain.get();
        assertEquals(userId, principal.userId());
        assertEquals("A", principal.status());
    }

    @Test
    void leavesReactiveExchangeUnchangedWhenGatewayHeaderModeIsDisabled() {
        ReactiveGatewayHeaderAuthenticationWebFilter filter = new ReactiveGatewayHeaderAuthenticationWebFilter(
                new PlatformSecurityProperties.GatewayHeaderProperties()
        );
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/orders")
                        .header("X-User-Id", UUID.randomUUID().toString())
                        .build()
        );
        AtomicReference<Principal> principalSeenByChain = new AtomicReference<>();
        WebFilterChain chain = webExchange -> webExchange.getPrincipal()
                .doOnNext(principalSeenByChain::set)
                .then();

        filter.filter(exchange, chain).block();

        assertNull(principalSeenByChain.get());
    }
}
