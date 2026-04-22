package io.github.jho951.platform.security.hybrid;

import io.github.jho951.platform.security.api.SecurityAuditPublisher;
import io.github.jho951.platform.security.web.PlatformSecurityServletFilter;
import io.github.jho951.platform.security.web.SecurityFailureResponseWriter;
import io.github.jho951.platform.security.web.SecurityIngressAdapter;
import jakarta.servlet.Filter;

/**
 * gateway가 hybrid mode에서 직접 조립할 수 있는 공식 platform-security 통합 표면이다.
 */
public final class PlatformSecurityGatewayIntegration {
    private final SecurityIngressAdapter securityIngressAdapter;
    private final PlatformSecurityServletFilter platformSecurityServletFilter;
    private final Filter gatewayHeaderAuthenticationFilter;
    private final SecurityFailureResponseWriter securityFailureResponseWriter;
    private final SecurityAuditPublisher securityAuditPublisher;

    public PlatformSecurityGatewayIntegration(
            SecurityIngressAdapter securityIngressAdapter,
            PlatformSecurityServletFilter platformSecurityServletFilter,
            Filter gatewayHeaderAuthenticationFilter,
            SecurityFailureResponseWriter securityFailureResponseWriter,
            SecurityAuditPublisher securityAuditPublisher
    ) {
        this.securityIngressAdapter = securityIngressAdapter;
        this.platformSecurityServletFilter = platformSecurityServletFilter;
        this.gatewayHeaderAuthenticationFilter = gatewayHeaderAuthenticationFilter;
        this.securityFailureResponseWriter = securityFailureResponseWriter;
        this.securityAuditPublisher = securityAuditPublisher;
    }

    public SecurityIngressAdapter securityIngressAdapter() {
        return securityIngressAdapter;
    }

    public PlatformSecurityServletFilter platformSecurityServletFilter() {
        return platformSecurityServletFilter;
    }

    public Filter gatewayHeaderAuthenticationFilter() {
        return gatewayHeaderAuthenticationFilter;
    }

    public SecurityFailureResponseWriter securityFailureResponseWriter() {
        return securityFailureResponseWriter;
    }

    public SecurityAuditPublisher securityAuditPublisher() {
        return securityAuditPublisher;
    }
}
