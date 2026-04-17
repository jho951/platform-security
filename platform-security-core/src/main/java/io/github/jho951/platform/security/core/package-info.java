/**
 * platform-security 정책 평가 runtime의 기본 구현이다.
 *
 * <p>API와 policy SPI를 조합해 인증, IP guard, rate limit, 사용자 추가 policy를
 * 순차 평가한다.</p>
 */
package io.github.jho951.platform.security.core;
