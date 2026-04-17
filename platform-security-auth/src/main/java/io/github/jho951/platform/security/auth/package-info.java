/**
 * 1계층 auth provider를 platform-security {@code SecurityContextResolver}와 issuance capability로
 * 연결하는 adapter 모듈이다.
 *
 * <p>현재 이 package의 일부 helper는 {@code com.auth.*} 타입을 공개 표면에 노출한다.
 * 기본 starter 경로에서 이 노출을 줄이려면 별도 auth bridge/support 모듈로 분리해야 한다.</p>
 */
package io.github.jho951.platform.security.auth;
