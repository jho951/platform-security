package io.github.jho951.platform.security.client;

import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import reactor.core.publisher.Mono;

/**
 * WebClient outbound 요청에 security propagation header를 붙인다.
 */
public final class SecurityWebClientExchangeFilterFunction implements ExchangeFilterFunction {
    @Override
    public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
        ClientRequest.Builder builder = ClientRequest.from(request);
        builder.headers(headers -> SecurityOutboundContextHolder.currentHeaders().forEach(headers::set));
        return next.exchange(builder.build());
    }
}
