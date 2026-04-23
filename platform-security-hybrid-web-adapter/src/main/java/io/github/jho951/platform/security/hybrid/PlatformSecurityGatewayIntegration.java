package io.github.jho951.platform.security.hybrid;

import io.github.jho951.platform.security.api.SecurityAuditPublisher;
import io.github.jho951.platform.security.web.SecurityFailureResponseWriter;
import jakarta.servlet.Filter;

/**
 * gateway가 hybrid mode에서 직접 조립할 수 있는 공식 platform-security Servlet 통합 표면이다.
 */
public final class PlatformSecurityGatewayIntegration {
    private final HybridSecurityRuntime securityRuntime;
    private final HybridRouteSecurityPolicy routeSecurityPolicy;
    private final HybridHeaderAuthenticationAdapter headerAuthenticationAdapter;
    private final Filter servletSecurityFilter;
    private final HybridFailureResponseContract failureResponseContract;
    private final SecurityAuditPublisher securityAuditPublisher;

    public PlatformSecurityGatewayIntegration(
            HybridSecurityRuntime securityRuntime,
            HybridRouteSecurityPolicy routeSecurityPolicy,
            HybridHeaderAuthenticationAdapter headerAuthenticationAdapter,
            Filter servletSecurityFilter,
            HybridFailureResponseContract failureResponseContract,
            SecurityAuditPublisher securityAuditPublisher
    ) {
        this.securityRuntime = securityRuntime;
        this.routeSecurityPolicy = routeSecurityPolicy;
        this.headerAuthenticationAdapter = headerAuthenticationAdapter;
        this.servletSecurityFilter = servletSecurityFilter;
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

    public Filter servletSecurityFilter() {
        return servletSecurityFilter;
    }

    public Filter gatewayHeaderAuthenticationFilter() {
        return headerAuthenticationAdapter.servletFilter().orElse(null);
    }

    public SecurityFailureResponseWriter securityFailureResponseWriter() {
        return failureResponseContract.servletWriter().orElse(null);
    }

    public HybridFailureResponseContract failureResponseContract() {
        return failureResponseContract;
    }

    public SecurityAuditPublisher securityAuditPublisher() {
        return securityAuditPublisher;
    }
}
