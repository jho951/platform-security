package io.github.jho951.platform.security.compat;

import io.github.jho951.platform.security.web.SecurityIngressContext;
import io.github.jho951.platform.security.web.SecurityRequestAttributeContributor;

import java.util.Map;

final class LegacySecretSecurityRequestAttributeContributor implements SecurityRequestAttributeContributor {
    @Override
    public void contribute(SecurityIngressContext context, Map<String, String> attributes) {
        String secret = header(context.headers(), "X-Internal-Request-Secret");
        if (secret != null) {
            attributes.put(LegacySecretInternalServiceCompatibilityAuthenticationAdapter.INTERNAL_REQUEST_SECRET_ATTRIBUTE, secret);
        }
    }

    private String header(Map<String, String> headers, String name) {
        if (headers == null) {
            return null;
        }
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey() != null && entry.getKey().trim().equalsIgnoreCase(name)) {
                String value = entry.getValue();
                if (value == null || value.isBlank()) {
                    return null;
                }
                return value.trim();
            }
        }
        return null;
    }
}
