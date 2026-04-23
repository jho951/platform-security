package io.github.jho951.platform.security.hybrid;

import io.github.jho951.platform.security.api.SecurityEvaluationResult;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.web.ReactiveSecurityFailureResponseWriter;
import io.github.jho951.platform.security.web.SecurityFailureResponse;
import io.github.jho951.platform.security.web.SecurityFailureResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.util.Optional;

/**
 * gateway/edge가 표준 실패 응답 생성과 쓰기를 official hybrid contract로 소비하는 표면이다.
 */
public final class HybridFailureResponseContract {
    private final SecurityFailureResponseWriter servletWriter;
    private final ReactiveSecurityFailureResponseWriter reactiveWriter;

    public HybridFailureResponseContract(
            SecurityFailureResponseWriter servletWriter,
            ReactiveSecurityFailureResponseWriter reactiveWriter
    ) {
        this.servletWriter = servletWriter;
        this.reactiveWriter = reactiveWriter;
    }

    public SecurityFailureResponse from(SecurityVerdict verdict) {
        return SecurityFailureResponse.from(verdict);
    }

    public SecurityFailureResponse from(SecurityEvaluationResult result) {
        return from(result.verdict());
    }

    public void write(HttpServletRequest request, HttpServletResponse response, SecurityVerdict verdict) throws IOException {
        write(request, response, from(verdict));
    }

    public void write(HttpServletRequest request, HttpServletResponse response, SecurityFailureResponse failure) throws IOException {
        servletWriter().orElseThrow(() -> new IllegalStateException("No servlet SecurityFailureResponseWriter configured"))
                .write(request, response, failure);
    }

    public Mono<Void> write(ServerWebExchange exchange, SecurityVerdict verdict) {
        return write(exchange, from(verdict));
    }

    public Mono<Void> write(ServerWebExchange exchange, SecurityFailureResponse failure) {
        return reactiveWriter().orElseThrow(() -> new IllegalStateException("No reactive SecurityFailureResponseWriter configured"))
                .write(exchange, failure);
    }

    public Optional<SecurityFailureResponseWriter> servletWriter() {
        return Optional.ofNullable(servletWriter);
    }

    public Optional<ReactiveSecurityFailureResponseWriter> reactiveWriter() {
        return Optional.ofNullable(reactiveWriter);
    }
}
