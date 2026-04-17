/**
 * servlet/reactive web 요청을 platform-security 요청 모델로 변환하고 필터로 연결하는 모듈이다.
 *
 * <p>client IP 해석, credential scrub, downstream identity header 생성, HTTP 실패 응답 매핑을
 * 담당한다.</p>
 */
package io.github.jho951.platform.security.web;
