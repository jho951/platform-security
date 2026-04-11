package io.github.jho951.platform.security.web;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public final class SecurityDownstreamHeaders {
    private final Map<String, String> headers;

    public SecurityDownstreamHeaders(Map<String, String> headers) {
        this.headers = headers == null ? Collections.emptyMap() : Collections.unmodifiableMap(new LinkedHashMap<>(headers));
    }

    public Map<String, String> asMap() {
        return headers;
    }

    public SecurityDownstreamHeaders withHeader(String name, String value) {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(value, "value");
        Map<String, String> copy = new LinkedHashMap<>(headers);
        copy.put(name, value);
        return new SecurityDownstreamHeaders(copy);
    }
}
