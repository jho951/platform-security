package io.github.jho951.platform.security.auth;

import com.auth.api.model.OAuth2UserIdentity;
import com.auth.api.model.Principal;
import com.auth.spi.OAuth2PrincipalResolver;

import java.util.Objects;

/**
 * auth 1계층 {@link OAuth2PrincipalResolver}를 platform bridge 인터페이스로 감싼다.
 *
 * <p>OAuth2 redirect와 code exchange는 소비 서비스가 끝낸 뒤, 그 결과 identity만
 * 이 bridge로 넘긴다.</p>
 */
public final class DefaultOAuth2PrincipalBridge implements OAuth2PrincipalBridge {
    private final OAuth2PrincipalResolver delegate;

    /**
     * OAuth2 principal resolver를 주입한다.
     *
     * @param delegate provider identity를 principal로 변환하는 resolver
     */
    public DefaultOAuth2PrincipalBridge(OAuth2PrincipalResolver delegate) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
    }

    @Override
    public Principal resolve(OAuth2UserIdentity identity) {
        return delegate.resolve(Objects.requireNonNull(identity, "identity"));
    }
}
