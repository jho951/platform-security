package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.hybrid.HybridAuthenticationContext;
import com.auth.hybrid.HybridAuthenticationProvider;

import java.util.Objects;
import java.util.Optional;

/**
 * 1계층 hybrid provider를 platform session support port로 감싼다.
 */
public final class DefaultPlatformSessionSupport implements PlatformSessionSupport {
    private final HybridAuthenticationProvider hybridAuthenticationProvider;

    public DefaultPlatformSessionSupport(HybridAuthenticationProvider hybridAuthenticationProvider) {
        this.hybridAuthenticationProvider = Objects.requireNonNull(hybridAuthenticationProvider, "hybridAuthenticationProvider");
    }

    @Override
    public Optional<Principal> authenticate(String accessToken, String sessionId) {
        return hybridAuthenticationProvider.authenticate(HybridAuthenticationContext.of(accessToken, sessionId));
    }
}
