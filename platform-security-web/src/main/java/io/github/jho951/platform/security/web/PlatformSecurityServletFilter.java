package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.api.SecurityEvaluationResult;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.time.Clock;
import java.util.Objects;

/**
 * servlet 요청을 platform-security 평가 흐름에 연결하는 filter다.
 *
 * <p>요청을 {@link SecurityRequest}로 변환하고, 인증 context를 해석한 뒤, 정책 평가와 감사
 * 발행을 수행한다. 실패 verdict는 JSON 오류 응답으로 반환한다.</p>
 */
public final class PlatformSecurityServletFilter implements Filter {
    private final SecurityIngressAdapter securityIngressAdapter;
    private final SecurityContextResolver securityContextResolver;
    private final Clock clock;
    private final SecurityIngressRequestFactory requestFactory;
    private final SecurityDownstreamIdentityPropagator downstreamIdentityPropagator;
    private final SecurityAuditPublisher auditPublisher;

    public PlatformSecurityServletFilter(
            SecurityIngressAdapter securityIngressAdapter,
            SecurityContextResolver securityContextResolver
    ) {
        this(securityIngressAdapter, securityContextResolver, Clock.systemUTC());
    }

    public PlatformSecurityServletFilter(
            SecurityIngressAdapter securityIngressAdapter,
            SecurityContextResolver securityContextResolver,
            Clock clock
    ) {
        this(securityIngressAdapter, securityContextResolver, clock, new SecurityIngressRequestFactory(
                new DefaultClientIpResolver(new PlatformSecurityProperties.IpGuardProperties()),
                new SecurityIdentityScrubber()
        ));
    }

    public PlatformSecurityServletFilter(
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
    }

    public PlatformSecurityServletFilter(
            SecurityIngressAdapter securityIngressAdapter,
            SecurityContextResolver securityContextResolver,
            Clock clock,
            SecurityIngressRequestFactory requestFactory,
            SecurityDownstreamIdentityPropagator downstreamIdentityPropagator,
            SecurityAuditPublisher auditPublisher
    ) {
        this.securityIngressAdapter = Objects.requireNonNull(securityIngressAdapter, "securityIngressAdapter");
        this.securityContextResolver = Objects.requireNonNull(securityContextResolver, "securityContextResolver");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.requestFactory = Objects.requireNonNull(requestFactory, "requestFactory");
        this.downstreamIdentityPropagator = Objects.requireNonNull(downstreamIdentityPropagator, "downstreamIdentityPropagator");
        this.auditPublisher = Objects.requireNonNull(auditPublisher, "auditPublisher");
    }

    @Override
    public void init(FilterConfig filterConfig) {
        // no-op
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest httpRequest) || !(response instanceof HttpServletResponse httpResponse)) {
            chain.doFilter(request, response);
            return;
        }

        SecurityRequest securityRequest = requestFactory.fromServlet(httpRequest, clock);
        SecurityContext securityContext = securityContextResolver.resolve(securityRequest);
        SecurityEvaluationResult evaluationResult = securityIngressAdapter.evaluateResult(securityRequest, securityContext);
        auditPublisher.publish(evaluationResult);
        SecurityFailureResponse failure = SecurityFailureResponse.from(evaluationResult.verdict());
        if (failure.status() != 200) {
            httpResponse.setStatus(failure.status());
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write("{\"code\":\"" + failure.code() + "\",\"message\":\"" + Objects.toString(failure.message(), "") + "\"}");
            return;
        }
        httpRequest.setAttribute(
                SecurityDownstreamIdentityPropagator.ATTR_DOWNSTREAM_HEADERS,
                downstreamIdentityPropagator.asAttributes(evaluationResult)
        );
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // no-op
    }
}
