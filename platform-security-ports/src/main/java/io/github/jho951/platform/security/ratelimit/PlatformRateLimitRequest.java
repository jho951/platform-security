package io.github.jho951.platform.security.ratelimit;

/**
 * platform-owned rate-limit adapter가 평가하는 요청 계약이다.
 *
 * @param key rate-limit key 값
 * @param keyType key 의미
 * @param permits 요청 permit 수
 * @param limit 허용 limit
 * @param windowSeconds quota window seconds
 */
public record PlatformRateLimitRequest(
        String key,
        PlatformRateLimitKeyType keyType,
        long permits,
        int limit,
        long windowSeconds
) {
    public PlatformRateLimitRequest {
        if (key == null || key.isBlank()) {
            throw new IllegalArgumentException("key must not be blank");
        }
        key = key.trim();
        keyType = keyType == null ? PlatformRateLimitKeyType.IP : keyType;
        permits = Math.max(1L, permits);
        if (limit <= 0) {
            throw new IllegalArgumentException("limit must be positive");
        }
        windowSeconds = Math.max(1L, windowSeconds);
    }
}
