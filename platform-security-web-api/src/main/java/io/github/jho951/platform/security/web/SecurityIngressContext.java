package io.github.jho951.platform.security.web;

import java.util.Map;

/**
 * ingress attribute contributor가 소비하는 읽기 전용 요청 context다.
 *
 * @param ingressType 요청 source 종류
 * @param principal 선택적 principal hint
 * @param clientIp 해석된 client IP
 * @param path 요청 path
 * @param action 요청 method/action
 * @param headers scrubbed inbound headers
 */
public record SecurityIngressContext(
        SecurityIngressType ingressType,
        String principal,
        String clientIp,
        String path,
        String action,
        Map<String, String> headers
) {
    public SecurityIngressContext {
        headers = headers == null ? Map.of() : Map.copyOf(headers);
    }
}
