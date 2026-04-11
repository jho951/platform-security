package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.api.SecurityEvaluationResult;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

import java.security.Principal;
import java.time.Clock;
import java.util.Objects;

public final class PlatformSecurityWebFilter implements WebFilter {
    private final SecurityIngressAdapter securityIngressAdapter;
    private final SecurityContextResolver securityContextResolver;
    private final Clock clock;
    private final SecurityIngressRequestFactory requestFactory;
    private final SecurityDownstreamIdentityPropagator downstreamIdentityPropagator = new SecurityDownstreamIdentityPropagator();

    public PlatformSecurityWebFilter(
            SecurityIngressAdapter securityIngressAdapter,
            SecurityContextResolver securityContextResolver
    ) {
        this(securityIngressAdapter, securityContextResolver, Clock.systemUTC());
    }

    public PlatformSecurityWebFilter(
            SecurityIngressAdapter securityIngressAdapter,
            SecurityContextResolver securityContextResolver,
            Clock clock
    ) {
        this(securityIngressAdapter, securityContextResolver, clock, new SecurityIngressRequestFactory(
                new DefaultClientIpResolver(new PlatformSecurityProperties.IpGuardProperties()),
                new SecurityIdentityScrubber()
        ));
    }

    public PlatformSecurityWebFilter(
            SecurityIngressAdapter securityIngressAdapter,
            SecurityContextResolver securityContextResolver,
            Clock clock,
            SecurityIngressRequestFactory requestFactory
    ) {
        this.securityIngressAdapter = Objects.requireNonNull(securityIngressAdapter, "securityIngressAdapter");
        this.securityContextResolver = Objects.requireNonNull(securityContextResolver, "securityContextResolver");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.requestFactory = Objects.requireNonNull(requestFactory, "requestFactory");
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(chain, "chain");

        return exchange.getPrincipal()
                .map(Principal::getName)
                .defaultIfEmpty("")
                .flatMap(principal -> {
                    SecurityRequest securityRequest = requestFactory.fromWebFlux(exchange, principal, clock);
                    SecurityContext securityContext = securityContextResolver.resolve(securityRequest);
                    SecurityEvaluationResult evaluationResult = securityIngressAdapter.evaluateResult(securityRequest, securityContext);
                    SecurityFailureResponse failure = SecurityFailureResponse.from(evaluationResult.verdict());
                    if (failure.status() != 200) {
                        exchange.getResponse().setStatusCode(HttpStatus.valueOf(failure.status()));
                        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
                        byte[] body = ("{\"code\":\"" + failure.code() + "\",\"message\":\"" + Objects.toString(failure.message(), "") + "\"}")
                                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(body)));
                    }
                    exchange.getAttributes().put(
                            SecurityDownstreamIdentityPropagator.ATTR_DOWNSTREAM_HEADERS,
                            downstreamIdentityPropagator.asAttributes(evaluationResult)
                    );
                    return chain.filter(exchange);
                });
    }
}
