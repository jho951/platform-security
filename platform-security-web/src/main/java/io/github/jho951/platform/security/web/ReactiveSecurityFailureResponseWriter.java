package io.github.jho951.platform.security.web;

import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * WebFlux 보안 실패 응답을 쓰는 확장점이다.
 *
 * <p>3계층 서비스가 자기 응답 포맷을 유지해야 할 때 bean으로 제공한다.</p>
 */
@FunctionalInterface
public interface ReactiveSecurityFailureResponseWriter {
    /**
     * 보안 실패 응답을 쓴다.
     *
     * @param exchange 현재 WebFlux exchange
     * @param failure 표준 보안 실패 응답
     * @return 응답 쓰기 완료 signal
     */
    Mono<Void> write(ServerWebExchange exchange, SecurityFailureResponse failure);

    /**
     * 기본 JSON writer를 반환한다.
     *
     * @return 기본 JSON writer
     */
    static ReactiveSecurityFailureResponseWriter json() {
        return new JsonReactiveSecurityFailureResponseWriter();
    }
}
