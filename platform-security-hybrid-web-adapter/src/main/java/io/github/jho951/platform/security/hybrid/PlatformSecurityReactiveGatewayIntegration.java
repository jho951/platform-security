package io.github.jho951.platform.security.hybrid;

import io.github.jho951.platform.security.api.SecurityAuditPublisher;
import io.github.jho951.platform.security.web.PlatformSecurityWebFilter;
import io.github.jho951.platform.security.web.ReactiveSecurityFailureResponseWriter;
import io.github.jho951.platform.security.web.SecurityIngressAdapter;
import org.springframework.web.server.WebFilter;

/**
 * gateway가 hybrid mode에서 직접 조립할 수 있는 공식 platform-security WebFlux 통합 표면이다.
 */
public final class PlatformSecurityReactiveGatewayIntegration {
    private final SecurityIngressAdapter securityIngressAdapter;
    private final PlatformSecurityWebFilter platformSecurityWebFilter;
    private final WebFilter gatewayHeaderAuthenticationWebFilter;
    private final ReactiveSecurityFailureResponseWriter reactiveSecurityFailureResponseWriter;
    private final SecurityAuditPublisher securityAuditPublisher;

    public PlatformSecurityReactiveGatewayIntegration(
            SecurityIngressAdapter securityIngressAdapter,
            PlatformSecurityWebFilter platformSecurityWebFilter,
            WebFilter gatewayHeaderAuthenticationWebFilter,
            ReactiveSecurityFailureResponseWriter reactiveSecurityFailureResponseWriter,
            SecurityAuditPublisher securityAuditPublisher
    ) {
        this.securityIngressAdapter = securityIngressAdapter;
        this.platformSecurityWebFilter = platformSecurityWebFilter;
        this.gatewayHeaderAuthenticationWebFilter = gatewayHeaderAuthenticationWebFilter;
        this.reactiveSecurityFailureResponseWriter = reactiveSecurityFailureResponseWriter;
        this.securityAuditPublisher = securityAuditPublisher;
    }

    public SecurityIngressAdapter securityIngressAdapter() {
        return securityIngressAdapter;
    }

    public PlatformSecurityWebFilter platformSecurityWebFilter() {
        return platformSecurityWebFilter;
    }

    public WebFilter gatewayHeaderAuthenticationWebFilter() {
        return gatewayHeaderAuthenticationWebFilter;
    }

    public ReactiveSecurityFailureResponseWriter reactiveSecurityFailureResponseWriter() {
        return reactiveSecurityFailureResponseWriter;
    }

    public SecurityAuditPublisher securityAuditPublisher() {
        return securityAuditPublisher;
    }
}
