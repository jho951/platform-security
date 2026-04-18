package io.github.jho951.platform.security.policy;

import java.util.Map;

/**
 * remote address와 proxy header에서 최종 client IP를 해석한다.
 *
 * <p>기본 구현은 trusted proxy exact IP 또는 CIDR에 속한 proxy에서 온
 * {@code X-Forwarded-For}만 신뢰하도록 구성할 수 있다.</p>
 */
public interface ClientIpResolver {
    /**
     * 요청의 실제 client IP를 반환한다.
     *
     * @param remoteAddress connection remote address
     * @param headers 정규화된 요청 header
     * @return 정책 평가에 사용할 client IP
     */
    String resolve(String remoteAddress, Map<String, String> headers);
}
