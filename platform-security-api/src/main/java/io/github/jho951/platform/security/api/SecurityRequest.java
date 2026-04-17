package io.github.jho951.platform.security.api;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

/**
 * platform-security가 소비하는 정규화된 요청 모델이다.
 *
 * <p>servlet, gateway, batch, service code adapter는 정책 평가 전에 각 요청을
 * 이 record로 변환한다. credential 값은 resolver가 소비하고 scrub할 수 있는
 * 최소 시간 동안만 attribute에 담아야 한다.</p>
 *
 * @param subject 호출자가 제공한 선택적 subject hint
 * @param clientIp 해석된 client IP 주소
 * @param path 요청 path 또는 resource path
 * @param action 수행하려는 동작. 예: READ, WRITE
 * @param attributes 정규화된 보안 attribute
 * @param occurredAt 요청 발생 시각
 */
public record SecurityRequest(
        String subject,
        String clientIp,
        String path,
        String action,
        Map<String, String> attributes,
        Instant occurredAt
) {
    public SecurityRequest {
        subject = blankToNull(subject);
        clientIp = requireText(clientIp, "clientIp");
        path = requireText(path, "path");
        action = requireText(action, "action");
        attributes = attributes == null ? Collections.emptyMap() : Map.copyOf(attributes);
        occurredAt = occurredAt == null ? Instant.now() : occurredAt;
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String requireText(String value, String field) {
        if (value == null ) throw new IllegalArgumentException(field + " must not be blank");
		if (value.isBlank()) throw new IllegalArgumentException(field + " must not be blank");
        return value.trim();
    }
}
