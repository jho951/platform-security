/**
 * 1계층 auth provider를 platform-security {@code SecurityContextResolver}와 issuance capability로
 * 연결하는 adapter 모듈이다.
 *
 * <p>핵심 capability, principal, issuance 계약은 platform 소유 타입만 공개한다.
 * 다만 조립 helper는 아직 {@code com.auth.*} SPI를 입력으로 받을 수 있으므로, 해당
 * 의존성은 auth 공개 surface와 publish metadata가 어긋나지 않게 {@code api} 범위로 유지한다.
 * raw auth bean graph를 platform port/capability로 연결하는 auto-configuration 등록은 optional
 * {@code platform-security-auth-bridge-starter}가 담당한다.</p>
 */
package io.github.jho951.platform.security.auth;
