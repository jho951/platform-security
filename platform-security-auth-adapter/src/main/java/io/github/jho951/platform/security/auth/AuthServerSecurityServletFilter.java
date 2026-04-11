package io.github.jho951.platform.security.auth;

import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.web.SecurityContextResolver;
import io.github.jho951.platform.security.web.SecurityFailureResponse;
import io.github.jho951.platform.security.web.SecurityIngressAdapter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public final class AuthServerSecurityServletFilter implements Filter {
    private final SecurityIngressAdapter securityIngressAdapter;
    private final SecurityContextResolver securityContextResolver;

    public AuthServerSecurityServletFilter(
            SecurityIngressAdapter securityIngressAdapter,
            SecurityContextResolver securityContextResolver
    ) {
        this.securityIngressAdapter = Objects.requireNonNull(securityIngressAdapter, "securityIngressAdapter");
        this.securityContextResolver = Objects.requireNonNull(securityContextResolver, "securityContextResolver");
    }

    @Override
    public void init(FilterConfig filterConfig) {}

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest httpRequest) || !(response instanceof HttpServletResponse httpResponse)) {
            chain.doFilter(request, response);
            return;
        }

        SecurityRequest securityRequest = new SecurityRequest(
                extractPrincipal(httpRequest),
                extractClientIp(httpRequest),
                httpRequest.getRequestURI(),
                httpRequest.getMethod(),
                extractAttributes(httpRequest),
                Instant.now()
        );

        SecurityFailureResponse failure = securityIngressAdapter.evaluateFailureResponse(
                securityRequest,
                securityContextResolver
        );

        if (failure.status() >= 400) {
            httpResponse.setStatus(failure.status());
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write(toJson(failure));
            return;
        }

        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {}

    private static String extractClientIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) return forwardedFor.split(",")[0].trim();
        return request.getRemoteAddr();
    }

    private static String extractPrincipal(HttpServletRequest request) {
        String principal = request.getHeader(AuthServerHeaderNames.PRINCIPAL);
        if (principal == null) return null;
		if (principal.isBlank()) return null;
        return principal.trim();
    }

    private static Map<String, String> extractAttributes(HttpServletRequest request) {
        Map<String, String> attributes = new LinkedHashMap<>();
        putIfPresent(attributes, AuthServerHeaderNames.ACCESS_TOKEN_ATTRIBUTE, extractBearerToken(request.getHeader(AuthServerHeaderNames.AUTHORIZATION)));
        putIfPresent(attributes, AuthServerHeaderNames.SESSION_ID_ATTRIBUTE, request.getHeader(AuthServerHeaderNames.SESSION_ID));
        putIfPresent(attributes, AuthServerHeaderNames.AUTHENTICATED, request.getHeader(AuthServerHeaderNames.AUTHENTICATED));
        putIfPresent(attributes, AuthServerHeaderNames.PRINCIPAL, request.getHeader(AuthServerHeaderNames.PRINCIPAL));
        putIfPresent(attributes, AuthServerHeaderNames.ROLES, request.getHeader(AuthServerHeaderNames.ROLES));
        return attributes;
    }

    private static String extractBearerToken(String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return null;
        }
        String trimmed = authorizationHeader.trim();
        if (trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) return trimToNull(trimmed.substring(7));
        return trimToNull(trimmed);
    }

    private static void putIfPresent(Map<String, String> attributes, String key, String value) {
        if (value != null && !value.isBlank()) attributes.put(toAttributeKey(key), value.trim());
    }

    private static String toAttributeKey(String headerName) {
        return switch (headerName) {
            case AuthServerHeaderNames.AUTHENTICATED -> AuthServerSecurityContextResolver.AUTHENTICATED_ATTRIBUTE;
            case AuthServerHeaderNames.PRINCIPAL -> AuthServerSecurityContextResolver.PRINCIPAL_ATTRIBUTE;
            case AuthServerHeaderNames.ROLES -> AuthServerSecurityContextResolver.ROLES_ATTRIBUTE;
            case AuthServerHeaderNames.ACCESS_TOKEN_ATTRIBUTE -> AuthServerSecurityContextResolver.ACCESS_TOKEN_ATTRIBUTE;
            case AuthServerHeaderNames.SESSION_ID_ATTRIBUTE -> AuthServerSecurityContextResolver.SESSION_ID_ATTRIBUTE;
            default -> headerName;
        };
    }

    private static String trimToNull(String value) {
        if (value == null) return null;
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static String toJson(SecurityFailureResponse response) {
        StringBuilder sb = new StringBuilder(96);
        sb.append('{');
        sb.append("\"code\":\"").append(escape(response.code())).append('\"');
        sb.append(",\"message\":");
        if (response.message() == null) {
            sb.append("null");
        } else {
            sb.append('\"').append(escape(response.message())).append('\"');
        }
        sb.append('}');
        return sb.toString();
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
