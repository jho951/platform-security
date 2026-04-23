package io.github.jho951.platform.security.hybrid;

import io.github.jho951.platform.security.api.SecurityAuditPublisher;
import io.github.jho951.platform.security.web.ReactiveSecurityFailureResponseWriter;
import org.springframework.web.server.WebFilter;

/**
 * gateway가 hybrid mode에서 직접 조립할 수 있는 공식 platform-security WebFlux 통합 표면이다.
 */
public final class PlatformSecurityReactiveGatewayIntegration {
    private final HybridSecurityRuntime securityRuntime;
    private final HybridRouteSecurityPolicy routeSecurityPolicy;
    private final HybridHeaderAuthenticationAdapter headerAuthenticationAdapter;
    private final WebFilter reactiveSecurityFilter;
    private final HybridFailureResponseContract failureResponseContract;
    private final SecurityAuditPublisher securityAuditPublisher;

    public PlatformSecurityReactiveGatewayIntegration(
            HybridSecurityRuntime securityRuntime,
            HybridRouteSecurityPolicy routeSecurityPolicy,
            HybridHeaderAuthenticationAdapter headerAuthenticationAdapter,
            WebFilter reactiveSecurityFilter,
            HybridFailureResponseContract failureResponseContract,
            SecurityAuditPublisher securityAuditPublisher
    ) {
        this.securityRuntime = securityRuntime;
        this.routeSecurityPolicy = routeSecurityPolicy;
        this.headerAuthenticationAdapter = headerAuthenticationAdapter;
        this.reactiveSecurityFilter = reactiveSecurityFilter;
        this.failureResponseContract = failureResponseContract;
        this.securityAuditPublisher = securityAuditPublisher;
    }

    public HybridSecurityRuntime securityRuntime() {
        return securityRuntime;
    }

    public HybridRouteSecurityPolicy routeSecurityPolicy() {
        return routeSecurityPolicy;
    }

    public HybridHeaderAuthenticationAdapter headerAuthenticationAdapter() {
        return headerAuthenticationAdapter;
    }

    public WebFilter reactiveSecurityFilter() {
        return reactiveSecurityFilter;
    }

    public WebFilter gatewayHeaderAuthenticationWebFilter() {
        return headerAuthenticationAdapter.reactiveWebFilter().orElse(null);
    }

    public ReactiveSecurityFailureResponseWriter reactiveSecurityFailureResponseWriter() {
        return failureResponseContract.reactiveWriter().orElse(null);
    }

    public HybridFailureResponseContract failureResponseContract() {
        return failureResponseContract;
    }

    public SecurityAuditPublisher securityAuditPublisher() {
        return securityAuditPublisher;
    }
}
