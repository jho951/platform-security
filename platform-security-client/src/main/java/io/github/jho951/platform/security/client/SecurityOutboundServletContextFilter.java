package io.github.jho951.platform.security.client;

import io.github.jho951.platform.security.web.SecurityDownstreamAttributes;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

import java.io.IOException;

/**
 * servlet request attribute에 저장된 downstream security headers를 outbound context로 연결한다.
 */
public final class SecurityOutboundServletContextFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) {
        // no-op
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        try {
            SecurityOutboundContextHolder.set(SecurityOutboundContextHolder.copyOf(
                    request.getAttribute(SecurityDownstreamAttributes.ATTR_DOWNSTREAM_HEADERS)
            ));
            chain.doFilter(request, response);
        } finally {
            SecurityOutboundContextHolder.clear();
        }
    }

    @Override
    public void destroy() {
        // no-op
    }
}
