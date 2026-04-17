package io.github.jho951.platform.security.policy;

import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Locale;
import java.util.Objects;

/**
 * boundary와 credential hint를 사용해 기본 client type을 추론한다.
 */
public final class DefaultClientTypeResolver implements ClientTypeResolver {
    @Override
    public ClientType resolve(SecurityRequest request) {
        return resolve(request, null, null);
    }

    @Override
    public ClientType resolve(SecurityRequest request, io.github.jho951.platform.security.api.SecurityContext context, SecurityBoundary boundary) {
        Objects.requireNonNull(request, "request");
        String boundaryType = boundary == null ? normalize(request.attributes().get(SecurityAttributes.BOUNDARY)) : boundary.type().name();
        if ("INTERNAL".equals(boundaryType)) {
            return ClientType.INTERNAL_SERVICE;
        }
        if ("ADMIN".equals(boundaryType)) {
            return ClientType.ADMIN_CONSOLE;
        }
        if (request.attributes().containsKey("auth.sessionId")) {
            return ClientType.BROWSER;
        }
        if (request.attributes().containsKey("auth.accessToken")) {
            return ClientType.EXTERNAL_API;
        }
        if (request.subject() != null) {
            return ClientType.EXTERNAL_API;
        }
        return ClientType.EXTERNAL_API;
    }

    private String normalize(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        return trimmed.toUpperCase(Locale.ROOT);
    }
}
