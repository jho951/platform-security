package io.github.jho951.platform.security.web;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/**
 * 기본 WebFlux JSON 보안 실패 응답 writer다.
 */
public final class JsonReactiveSecurityFailureResponseWriter implements ReactiveSecurityFailureResponseWriter {
    @Override
    public Mono<Void> write(ServerWebExchange exchange, SecurityFailureResponse failure) {
        exchange.getResponse().setStatusCode(HttpStatus.valueOf(failure.status()));
        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
        byte[] body = SecurityFailureResponseJson.toJson(failure).getBytes(StandardCharsets.UTF_8);
        return exchange.getResponse()
                .writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(body)));
    }
}
