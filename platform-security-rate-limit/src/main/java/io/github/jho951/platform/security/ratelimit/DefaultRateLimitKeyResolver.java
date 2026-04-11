package io.github.jho951.platform.security.ratelimit;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.ResolvedSecurityProfile;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.policy.AuthMode;
import io.github.jho951.platform.security.policy.ClientType;
import io.github.jho951.platform.security.policy.RateLimitKeyResolver;
import io.github.jho951.platform.security.policy.SecurityAttributes;

import java.util.Locale;
import java.util.Objects;

public final class DefaultRateLimitKeyResolver implements RateLimitKeyResolver {
    @Override
    public String resolve(SecurityRequest request, SecurityContext context) {
        return resolve(request, context, null);
    }

    @Override
    public String resolve(SecurityRequest request, SecurityContext context, ResolvedSecurityProfile profile) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(context, "context");
        String boundary = profile == null ? normalize(request.attributes().get(SecurityAttributes.BOUNDARY)) : profile.boundaryType();
        String clientType = profile == null ? normalize(request.attributes().get(SecurityAttributes.CLIENT_TYPE)) : profile.clientType();
        String authMode = profile == null ? normalize(request.attributes().get(SecurityAttributes.AUTH_MODE)) : profile.authMode();
        if (boundary == null) {
            boundary = "PROTECTED";
        }
        if (clientType == null) {
            clientType = context.authenticated() ? ClientType.EXTERNAL_API.name() : ClientType.EXTERNAL_API.name();
        }
        if (authMode == null) {
            authMode = context.authenticated() ? AuthMode.HYBRID.name() : AuthMode.NONE.name();
        }
        String subject = context.principal() != null ? context.principal() : request.subject();
        String subjectOrIp = subject != null ? subject : request.clientIp();
        return boundary + ":" + clientType + ":" + authMode + ":" + subjectOrIp;
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
