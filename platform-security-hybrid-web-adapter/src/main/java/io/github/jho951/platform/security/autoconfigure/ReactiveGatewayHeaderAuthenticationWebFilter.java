package io.github.jho951.platform.security.autoconfigure;

import io.github.jho951.platform.security.api.GatewayUserPrincipal;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebExchangeDecorator;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.security.Principal;
import java.util.UUID;

final class ReactiveGatewayHeaderAuthenticationWebFilter implements WebFilter {
    private final PlatformSecurityProperties.GatewayHeaderProperties properties;

    ReactiveGatewayHeaderAuthenticationWebFilter(PlatformSecurityProperties.GatewayHeaderProperties properties) {
        this.properties = properties == null
                ? new PlatformSecurityProperties.GatewayHeaderProperties()
                : properties;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (!properties.isEnabled()) {
            return chain.filter(exchange);
        }

        return exchange.getPrincipal()
                .cast(Principal.class)
                .flatMap(existingPrincipal -> chain.filter(exchange))
                .switchIfEmpty(Mono.defer(() -> {
                    GatewayUserPrincipal principal = resolvePrincipal(exchange);
                    if (principal == null) {
                        return chain.filter(exchange);
                    }
                    return chain.filter(exchangeWithPrincipal(exchange, principal));
                }));
    }

    private GatewayUserPrincipal resolvePrincipal(ServerWebExchange exchange) {
        String userIdHeader = trimToNull(exchange.getRequest().getHeaders().getFirst(properties.getUserIdHeader()));
        if (userIdHeader == null) {
            return null;
        }

        UUID userId;
        try {
            userId = UUID.fromString(userIdHeader);
        } catch (IllegalArgumentException ignored) {
            return null;
        }

        String status = trimToNull(exchange.getRequest().getHeaders().getFirst(properties.getUserStatusHeader()));
        return new GatewayUserPrincipal(userId, status);
    }

    private static ServerWebExchange exchangeWithPrincipal(ServerWebExchange exchange, GatewayUserPrincipal principal) {
        return new ServerWebExchangeDecorator(exchange) {
            @Override
            @SuppressWarnings("unchecked")
            public <T extends Principal> Mono<T> getPrincipal() {
                return (Mono<T>) Mono.just(principal);
            }
        };
    }

    private static String trimToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }
}
