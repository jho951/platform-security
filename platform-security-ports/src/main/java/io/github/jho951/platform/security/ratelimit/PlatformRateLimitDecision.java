package io.github.jho951.platform.security.ratelimit;

/**
 * platform-owned rate-limit adapter가 반환하는 판정 결과다.
 *
 * @param allowed 요청 허용 여부
 * @param key 판정에 사용한 key
 * @param detail 진단 메시지
 */
public record PlatformRateLimitDecision(
        boolean allowed,
        String key,
        String detail
) {
    public static PlatformRateLimitDecision allow(String key, String detail) {
        return new PlatformRateLimitDecision(true, key, detail);
    }

    public static PlatformRateLimitDecision deny(String key, String detail) {
        return new PlatformRateLimitDecision(false, key, detail);
    }
}
