package io.github.jho951.platform.security.compat;

import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.auth.InternalServiceCompatibilityAuthenticationAdapter;
import io.github.jho951.platform.security.auth.PlatformAuthenticatedPrincipal;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

final class LegacySecretInternalServiceCompatibilityAuthenticationAdapter
        implements InternalServiceCompatibilityAuthenticationAdapter {
    static final String INTERNAL_REQUEST_SECRET_ATTRIBUTE = "auth.internalRequestSecret";

    private final PlatformSecurityProperties.LegacySecretProperties properties;

    LegacySecretInternalServiceCompatibilityAuthenticationAdapter(
            PlatformSecurityProperties.LegacySecretProperties properties
    ) {
        this.properties = properties == null
                ? new PlatformSecurityProperties.LegacySecretProperties()
                : properties;
    }

    @Override
    public Optional<PlatformAuthenticatedPrincipal> authenticate(SecurityRequest request) {
        if (!properties.isEnabled()) {
            return Optional.empty();
        }

        String expected = trimToNull(properties.getSecret());
        String provided = trimToNull(request.attributes().get(INTERNAL_REQUEST_SECRET_ATTRIBUTE));
        if (expected == null || provided == null || !constantTimeEquals(expected, provided)) {
            return Optional.empty();
        }

        Set<String> authorities = properties.getAuthorities().stream()
                .map(LegacySecretInternalServiceCompatibilityAuthenticationAdapter::trimToNull)
                .filter(java.util.Objects::nonNull)
                .collect(Collectors.toUnmodifiableSet());

        return Optional.of(new PlatformAuthenticatedPrincipal(
                properties.getPrincipalId(),
                authorities,
                Map.of("auth.compatibility", "legacy-secret")
        ));
    }

    private static boolean constantTimeEquals(String expected, String provided) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                provided.getBytes(StandardCharsets.UTF_8)
        );
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
