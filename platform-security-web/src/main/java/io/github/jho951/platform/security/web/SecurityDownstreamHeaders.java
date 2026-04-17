package io.github.jho951.platform.security.web;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * downstream 호출로 전달할 security header 묶음이다.
 */
public final class SecurityDownstreamHeaders {
    private final Map<String, String> headers;

    /**
     * @param headers downstream에 전달할 header map
     */
    public SecurityDownstreamHeaders(Map<String, String> headers) {
        this.headers = headers == null ? Collections.emptyMap() : Collections.unmodifiableMap(new LinkedHashMap<>(headers));
    }

    /**
     * @return 불변 header map
     */
    public Map<String, String> asMap() {
        return headers;
    }

    /**
     * header 하나를 추가한 새 객체를 반환한다.
     */
    public SecurityDownstreamHeaders withHeader(String name, String value) {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(value, "value");
        Map<String, String> copy = new LinkedHashMap<>(headers);
        copy.put(name, value);
        return new SecurityDownstreamHeaders(copy);
    }
}
