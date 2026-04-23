package io.github.jho951.platform.security.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Servlet 보안 실패 응답을 쓰는 확장점이다.
 *
 * <p>3계층 서비스가 자기 응답 포맷을 유지해야 할 때 bean으로 제공한다.</p>
 */
@FunctionalInterface
public interface SecurityFailureResponseWriter {
    /**
     * 보안 실패 응답을 쓴다.
     *
     * @param request 현재 servlet 요청
     * @param response 현재 servlet 응답
     * @param failure 표준 보안 실패 응답
     * @throws IOException 응답 쓰기 실패
     */
    void write(HttpServletRequest request, HttpServletResponse response, SecurityFailureResponse failure) throws IOException;

    /**
     * 기본 JSON writer를 반환한다.
     *
     * @return 기본 JSON writer
     */
    static SecurityFailureResponseWriter json() {
        return new JsonSecurityFailureResponseWriter();
    }
}
