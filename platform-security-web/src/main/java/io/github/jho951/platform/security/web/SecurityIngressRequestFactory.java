package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.policy.ClientIpResolver;
import org.springframework.web.server.ServerWebExchange;

import jakarta.servlet.http.HttpServletRequest;

import java.time.Clock;
import java.time.Instant;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * servlet 또는 WebFlux 요청을 {@link SecurityRequest}로 변환한다.
 */
public final class SecurityIngressRequestFactory {
    private final ClientIpResolver clientIpResolver;
    private final SecurityIdentityScrubber securityIdentityScrubber;

    /**
     * @param clientIpResolver client IP resolver
     * @param securityIdentityScrubber header scrubber
     */
    public SecurityIngressRequestFactory(ClientIpResolver clientIpResolver, SecurityIdentityScrubber securityIdentityScrubber) {
        this.clientIpResolver = Objects.requireNonNull(clientIpResolver, "clientIpResolver");
        this.securityIdentityScrubber = Objects.requireNonNull(securityIdentityScrubber, "securityIdentityScrubber");
    }

    /**
     * servlet 요청을 security request로 변환한다.
     */
    public SecurityRequest fromServlet(HttpServletRequest request, Clock clock) {
        Map<String, String> headers = scrubbedHeaders(requestHeaders(request));
        return new SecurityRequest(
                request.getUserPrincipal() == null ? null : request.getUserPrincipal().getName(),
                clientIpResolver.resolve(request.getRemoteAddr(), headers),
                request.getRequestURI(),
                request.getMethod(),
                requestAttributes(request, headers),
                Instant.now(clock)
        );
    }

    /**
     * WebFlux exchange를 security request로 변환한다.
     */
    public SecurityRequest fromWebFlux(ServerWebExchange exchange, String principal, Clock clock) {
        Map<String, String> headers = scrubbedHeaders(exchange.getRequest().getHeaders().toSingleValueMap());
        return new SecurityRequest(
                trimToNull(principal),
                clientIpResolver.resolve(remoteAddress(exchange), headers),
                exchange.getRequest().getPath().value(),
                exchange.getRequest().getMethod() == null ? "GET" : exchange.getRequest().getMethod().name(),
                requestAttributes(exchange, principal, headers),
                Instant.now(clock)
        );
    }

    private Map<String, String> requestAttributes(HttpServletRequest request, Map<String, String> headers) {
        Map<String, String> attributes = new LinkedHashMap<>();
        putIfPresent(attributes, "auth.accessToken", extractBearerToken(header(headers, "Authorization")));
        putIfPresent(attributes, "auth.sessionId", header(headers, "X-Auth-Session-Id"));
        putCredentialAttributes(attributes, headers);
        putHmacSignedHeaders(attributes, headers);
        attributes.put("auth.authenticated", Boolean.toString(request.getUserPrincipal() != null));
        attributes.put("auth.principal", request.getUserPrincipal() == null ? "" : request.getUserPrincipal().getName());
        return Map.copyOf(attributes);
    }

    private Map<String, String> requestAttributes(ServerWebExchange exchange, String principal, Map<String, String> headers) {
        Map<String, String> attributes = new LinkedHashMap<>();
        putIfPresent(attributes, "auth.accessToken", extractBearerToken(header(headers, "Authorization")));
        putIfPresent(attributes, "auth.sessionId", header(headers, "X-Auth-Session-Id"));
        putCredentialAttributes(attributes, headers);
        putHmacSignedHeaders(attributes, headers);
        attributes.put("auth.authenticated", Boolean.toString(principal != null && !principal.isBlank()));
        attributes.put("auth.principal", principal == null ? "" : principal.trim());
        return Map.copyOf(attributes);
    }

    private void putCredentialAttributes(Map<String, String> attributes, Map<String, String> headers) {
        putIfPresent(attributes, "auth.apiKeyId", header(headers, "X-Auth-Api-Key-Id"));
        putIfPresent(attributes, "auth.apiKeySecret", header(headers, "X-Auth-Api-Key-Secret"));
        putIfPresent(attributes, "auth.hmac.keyId", header(headers, "X-Auth-Hmac-Key-Id"));
        putIfPresent(attributes, "auth.hmac.signature", header(headers, "X-Auth-Hmac-Signature"));
        putIfPresent(attributes, "auth.hmac.timestamp", header(headers, "X-Auth-Hmac-Timestamp"));
        putIfPresent(attributes, "auth.oidc.idToken", header(headers, "X-Auth-Oidc-Id-Token"));
        putIfPresent(attributes, "auth.oidc.nonce", header(headers, "X-Auth-Oidc-Nonce"));
        putIfPresent(attributes, "auth.serviceAccountId", header(headers, "X-Auth-Service-Account-Id"));
        putIfPresent(attributes, "auth.serviceAccountSecret", header(headers, "X-Auth-Service-Account-Secret"));
    }

    private void putHmacSignedHeaders(Map<String, String> attributes, Map<String, String> headers) {
        String signedHeaders = header(headers, "X-Auth-Hmac-Signed-Headers");
        if (signedHeaders == null || signedHeaders.isBlank()) {
            return;
        }
        for (String headerName : signedHeaders.split(",")) {
            String normalized = trimToNull(headerName);
            if (normalized != null) {
                putIfPresent(attributes, "auth.hmac.header." + normalized, header(headers, normalized));
            }
        }
    }

    private Map<String, String> scrubbedHeaders(Map<String, String> headers) {
        return securityIdentityScrubber.scrub(headers);
    }

    private Map<String, String> requestHeaders(HttpServletRequest request) {
        Map<String, String> headers = new LinkedHashMap<>();
        for (Enumeration<String> names = request.getHeaderNames(); names != null && names.hasMoreElements(); ) {
            String name = names.nextElement();
            headers.put(name, request.getHeader(name));
        }
        return headers;
    }

    private String remoteAddress(ServerWebExchange exchange) {
        if (exchange.getRequest().getRemoteAddress() != null && exchange.getRequest().getRemoteAddress().getAddress() != null) {
            return exchange.getRequest().getRemoteAddress().getAddress().getHostAddress();
        }
        return "127.0.0.1";
    }

    private String extractBearerToken(String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return null;
        }
        String trimmed = authorizationHeader.trim();
        if (trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return trimToNull(trimmed.substring(7));
        }
        return trimToNull(trimmed);
    }

    private void putIfPresent(Map<String, String> attributes, String key, String value) {
        if (value != null && !value.isBlank()) {
            attributes.put(key, value.trim());
        }
    }

    private String header(Map<String, String> headers, String name) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey() != null && entry.getKey().trim().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return null;
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
