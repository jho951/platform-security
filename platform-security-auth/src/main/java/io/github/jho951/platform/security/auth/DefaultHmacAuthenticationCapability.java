package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.hmac.HmacAuthenticationProvider;
import com.auth.hmac.HmacAuthenticationRequest;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public final class DefaultHmacAuthenticationCapability implements AuthenticationCapability {
    private static final String SIGNED_HEADER_PREFIX = "auth.hmac.header.";

    private final HmacAuthenticationProvider hmacAuthenticationProvider;

    public DefaultHmacAuthenticationCapability(HmacAuthenticationProvider hmacAuthenticationProvider) {
        this.hmacAuthenticationProvider = Objects.requireNonNull(hmacAuthenticationProvider, "hmacAuthenticationProvider");
    }

    @Override
    public String name() {
        return "hmac";
    }

    @Override
    public Optional<Principal> authenticate(SecurityRequest request) {
        Map<String, String> attributes = request.attributes();
        String keyId = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.HMAC_KEY_ID_ATTRIBUTE));
        String signature = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.HMAC_SIGNATURE_ATTRIBUTE));
        if (keyId == null || signature == null) {
            return Optional.empty();
        }
        HmacAuthenticationRequest authenticationRequest = new HmacAuthenticationRequest(
                keyId,
                request.action(),
                request.path(),
                body(attributes),
                signedHeaders(attributes),
                signature,
                timestamp(attributes, request.occurredAt())
        );
        return hmacAuthenticationProvider.authenticate(authenticationRequest);
    }

    private byte[] body(Map<String, String> attributes) {
        String body = attributes.get(PlatformAuthenticationFacade.HMAC_BODY_ATTRIBUTE);
        return body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
    }

    private Map<String, String> signedHeaders(Map<String, String> attributes) {
        Map<String, String> headers = new LinkedHashMap<>();
        attributes.forEach((key, value) -> {
            if (key != null && key.startsWith(SIGNED_HEADER_PREFIX)) {
                String headerName = key.substring(SIGNED_HEADER_PREFIX.length()).trim();
                if (!headerName.isEmpty() && value != null) {
                    headers.put(headerName, value);
                }
            }
        });
        return Map.copyOf(headers);
    }

    private Instant timestamp(Map<String, String> attributes, Instant fallback) {
        String value = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.HMAC_TIMESTAMP_ATTRIBUTE));
        if (value == null) {
            return fallback;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException ignored) {
            return fallback;
        }
    }
}
