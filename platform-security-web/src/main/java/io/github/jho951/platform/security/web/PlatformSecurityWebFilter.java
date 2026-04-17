package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.api.SecurityAuditEvent;
import io.github.jho951.platform.security.api.SecurityAuditPublisher;
import io.github.jho951.platform.security.api.SecurityEvaluationResult;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

import java.security.Principal;
import java.time.Clock;
import java.util.Objects;

/**
 * WebFlux 요청을 platform-security 평가 흐름에 연결하는 reactive filter다.
 */
public final class PlatformSecurityWebFilter implements WebFilter {
    private final SecurityIngressAdapter securityIngressAdapter;
    private final SecurityContextResolver securityContextResolver;
    private final Clock clock;
    private final SecurityIngressRequestFactory requestFactory;
    private final SecurityDownstreamIdentityPropagator downstreamIdentityPropagator;
    private final SecurityAuditPublisher auditPublisher;
    private final ReactiveSecurityFailureResponseWriter failureResponseWriter;

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
        this.downstreamIdentityPropagator = new SecurityDownstreamIdentityPropagator();
        this.auditPublisher = SecurityAuditPublisher.noop();
        this.failureResponseWriter = ReactiveSecurityFailureResponseWriter.json();
    }

    public PlatformSecurityWebFilter(
            SecurityIngressAdapter securityIngressAdapter,
            SecurityContextResolver securityContextResolver,
            Clock clock,
            SecurityIngressRequestFactory requestFactory,
            SecurityDownstreamIdentityPropagator downstreamIdentityPropagator,
            SecurityAuditPublisher auditPublisher
    ) {
        this(
                securityIngressAdapter,
                securityContextResolver,
                clock,
                requestFactory,
                downstreamIdentityPropagator,
                auditPublisher,
                ReactiveSecurityFailureResponseWriter.json()
        );
    }

    public PlatformSecurityWebFilter(
            SecurityIngressAdapter securityIngressAdapter,
            SecurityContextResolver securityContextResolver,
            Clock clock,
            SecurityIngressRequestFactory requestFactory,
            SecurityDownstreamIdentityPropagator downstreamIdentityPropagator,
            SecurityAuditPublisher auditPublisher,
            ReactiveSecurityFailureResponseWriter failureResponseWriter
    ) {
        this.securityIngressAdapter = Objects.requireNonNull(securityIngressAdapter, "securityIngressAdapter");
        this.securityContextResolver = Objects.requireNonNull(securityContextResolver, "securityContextResolver");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.requestFactory = Objects.requireNonNull(requestFactory, "requestFactory");
        this.downstreamIdentityPropagator = Objects.requireNonNull(downstreamIdentityPropagator, "downstreamIdentityPropagator");
        this.auditPublisher = Objects.requireNonNull(auditPublisher, "auditPublisher");
        this.failureResponseWriter = Objects.requireNonNull(failureResponseWriter, "failureResponseWriter");
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(chain, "chain");

        return exchange.getPrincipal()
                .map(Principal::getName)
                .defaultIfEmpty("")
                .flatMap(principal -> {
                    SecurityRequest securityRequest = securityIngressAdapter.withResolvedBoundary(requestFactory.fromWebFlux(exchange, principal, clock));
                    SecurityContext securityContext = securityContextResolver.resolve(securityRequest);
                    SecurityEvaluationResult evaluationResult = securityIngressAdapter.evaluateResult(securityRequest, securityContext);
                    auditPublisher.publish(SecurityAuditEvent.from(evaluationResult));
                    SecurityFailureResponse failure = SecurityFailureResponse.from(evaluationResult.verdict());
                    if (failure.status() != 200) {
                        return failureResponseWriter.write(exchange, failure);
                    }
                    exchange.getAttributes().put(
                            SecurityDownstreamIdentityPropagator.ATTR_DOWNSTREAM_HEADERS,
                            downstreamIdentityPropagator.asAttributes(evaluationResult)
                    );
                    return chain.filter(exchange);
                });
    }
}
