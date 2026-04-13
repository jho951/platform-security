package io.github.jho951.platform.security.auth;

import com.auth.api.model.OAuth2UserIdentity;
import com.auth.api.model.Principal;
import com.auth.spi.OAuth2PrincipalResolver;

import java.util.Objects;

public final class DefaultOAuth2PrincipalBridge implements OAuth2PrincipalBridge {
    private final OAuth2PrincipalResolver delegate;

    public DefaultOAuth2PrincipalBridge(OAuth2PrincipalResolver delegate) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
    }

    @Override
    public Principal resolve(OAuth2UserIdentity identity) {
        return delegate.resolve(Objects.requireNonNull(identity, "identity"));
    }
}
