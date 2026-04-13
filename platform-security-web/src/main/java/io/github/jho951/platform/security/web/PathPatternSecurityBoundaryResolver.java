package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.policy.SecurityBoundary;
import io.github.jho951.platform.security.policy.SecurityBoundaryType;

import java.util.List;
import java.util.Objects;

public final class PathPatternSecurityBoundaryResolver implements io.github.jho951.platform.security.policy.SecurityBoundaryResolver {
    private final List<String> publicPaths;
    private final List<String> protectedPaths;
    private final List<String> adminPaths;
    private final List<String> internalPaths;

	private boolean matches(String path, List<String> patterns, String... defaults) {
		for (String pattern : patterns) {
			if (pattern != null && matchesPattern(path, pattern)) return true;
		}
		for (String pattern : defaults) {
			if (matchesPattern(path, pattern)) return true;
		}
		return false;
	}

	private boolean matchesPattern(String path, String pattern) {
		if (pattern == null) return false;
		if (pattern.isBlank()) return false;
		String normalized = pattern.trim();
		if (normalized.endsWith("/**")) {
			String prefix = normalized.substring(0, normalized.length() - 3);
			return path.startsWith(prefix);
		}
		return path.equals(normalized) || path.startsWith(normalized + "/");
	}

    public PathPatternSecurityBoundaryResolver() {
        this(List.of(), List.of(), List.of(), List.of());
    }

    public PathPatternSecurityBoundaryResolver(
            List<String> publicPaths,
            List<String> protectedPaths,
            List<String> adminPaths,
            List<String> internalPaths
    ) {
        this.publicPaths = publicPaths == null ? List.of() : List.copyOf(publicPaths);
        this.protectedPaths = protectedPaths == null ? List.of() : List.copyOf(protectedPaths);
        this.adminPaths = adminPaths == null ? List.of() : List.copyOf(adminPaths);
        this.internalPaths = internalPaths == null ? List.of() : List.copyOf(internalPaths);
    }

    @Override
    public SecurityBoundary resolve(SecurityRequest request) {
        Objects.requireNonNull(request, "request");
        String path = resolvePath(request.path());
        if (matches(path, internalPaths, "/internal/", "/internal")) {
            return new SecurityBoundary(SecurityBoundaryType.INTERNAL, internalPaths);
        }
        if (matches(path, adminPaths, "/admin/", "/admin")) {
            return new SecurityBoundary(SecurityBoundaryType.ADMIN, adminPaths);
        }
        if (matches(path, publicPaths, "/health", "/actuator/health")) {
            return new SecurityBoundary(SecurityBoundaryType.PUBLIC, publicPaths);
        }
        if (matches(path, protectedPaths, "/api/", "/api")) {
            return new SecurityBoundary(SecurityBoundaryType.PROTECTED, protectedPaths);
        }
        return new SecurityBoundary(SecurityBoundaryType.PROTECTED, protectedPaths);
    }

    public String resolvePath(String requestPath) {
        Objects.requireNonNull(requestPath, "requestPath");
        String normalized = requestPath.trim();
        if (normalized.isEmpty()) throw new IllegalArgumentException("requestPath must not be blank");
        return normalized.startsWith("/") ? normalized : "/" + normalized;
    }
}
