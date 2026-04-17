/**
 * platform-security의 boundary-aware rate limit 구현을 담는다.
 *
 * <p>운영에서는 이 모듈의 policy가 공유 {@code RateLimiter} bean을 사용하도록
 * auto-configuration이 연결한다.</p>
 */
package io.github.jho951.platform.security.ratelimit;
