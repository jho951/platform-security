/**
 * platform-security의 boundary-aware rate limit 구현을 담는다.
 *
 * <p>기본 starter는 public contract인 {@code PlatformRateLimitPort}만 본다.
 * raw {@code RateLimiter} 연결 auto-configuration은 optional
 * {@code platform-security-ratelimit-bridge-starter}가 등록한다.</p>
 */
package io.github.jho951.platform.security.ratelimit;
