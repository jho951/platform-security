package io.github.jho951.platform.security.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * 기본 Servlet JSON 보안 실패 응답 writer다.
 */
public final class JsonSecurityFailureResponseWriter implements SecurityFailureResponseWriter {
    @Override
    public void write(
            HttpServletRequest request,
            HttpServletResponse response,
            SecurityFailureResponse failure
    ) throws IOException {
        response.setStatus(failure.status());
        response.setContentType("application/json");
        response.getWriter().write(SecurityFailureResponseJson.toJson(failure));
    }
}
