package io.github.jho951.platform.security.hybrid;

import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.policy.SecurityBoundary;

import java.util.Objects;
import java.util.function.Function;
import java.util.function.UnaryOperator;

/**
 * gateway/edge가 route 분류와 boundary 부착을 low-level resolver 없이 소비하는 공식 표면이다.
 */
public final class HybridRouteSecurityPolicy {
    private final Function<SecurityRequest, SecurityBoundary> securityBoundaryResolver;
    private final UnaryOperator<SecurityRequest> boundaryWriter;

    public HybridRouteSecurityPolicy(
            Function<SecurityRequest, SecurityBoundary> securityBoundaryResolver,
            UnaryOperator<SecurityRequest> boundaryWriter
    ) {
        this.securityBoundaryResolver = Objects.requireNonNull(securityBoundaryResolver, "securityBoundaryResolver");
        this.boundaryWriter = Objects.requireNonNull(boundaryWriter, "boundaryWriter");
    }

    public SecurityBoundary resolve(SecurityRequest request) {
        return securityBoundaryResolver.apply(request);
    }

    public String classify(SecurityRequest request) {
        return resolve(request).type().name();
    }

    public SecurityRequest withResolvedBoundary(SecurityRequest request) {
        return boundaryWriter.apply(request);
    }
}
