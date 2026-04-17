/**
 * platform-security의 정책 설정, resolver, override SPI를 담는 모듈이다.
 *
 * <p>3계층 서비스가 직접 알아야 하는 주요 확장 지점은 이 package에 있다. 실제 auth,
 * IP guard, rate limiter 구현체는 다른 모듈에서 이 계약을 소비한다.</p>
 */
package io.github.jho951.platform.security.policy;
