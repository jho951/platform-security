package io.github.jho951.platform.security.autoconfigure;

import io.github.jho951.platform.security.api.GatewayUserPrincipal;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

final class GatewayHeaderAuthenticationFilter extends OncePerRequestFilter {
    private final PlatformSecurityProperties.GatewayHeaderProperties properties;

    GatewayHeaderAuthenticationFilter(PlatformSecurityProperties.GatewayHeaderProperties properties) {
        this.properties = properties == null
                ? new PlatformSecurityProperties.GatewayHeaderProperties()
                : properties;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        if (!properties.isEnabled() || SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        String userIdHeader = request.getHeader(properties.getUserIdHeader());
        if (userIdHeader == null || userIdHeader.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        UUID userId;
        try {
            userId = UUID.fromString(userIdHeader.trim());
        } catch (IllegalArgumentException ignored) {
            filterChain.doFilter(request, response);
            return;
        }

        String status = trimToNull(request.getHeader(properties.getUserStatusHeader()));
        GatewayUserPrincipal principal = new GatewayUserPrincipal(userId, status);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                principal,
                null,
                authorities(status)
        );
        authentication.setDetails(request);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);
    }

    private List<GrantedAuthority> authorities(String status) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        addAuthority(authorities, properties.getUserAuthority());
        if (status != null) {
            addAuthority(authorities, properties.getStatusAuthorityPrefix() + status);
            if (status.equalsIgnoreCase(trimToNull(properties.getActiveStatus()))) {
                addAuthority(authorities, properties.getActiveStatusAuthority());
            }
        }
        return List.copyOf(authorities);
    }

    private static void addAuthority(List<GrantedAuthority> authorities, String authority) {
        String value = trimToNull(authority);
        if (value != null) {
            authorities.add(new SimpleGrantedAuthority(value));
        }
    }

    private static String trimToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }
}
