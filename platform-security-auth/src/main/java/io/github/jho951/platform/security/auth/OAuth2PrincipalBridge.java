package io.github.jho951.platform.security.auth;

import com.auth.api.model.OAuth2UserIdentity;
import com.auth.api.model.Principal;

public interface OAuth2PrincipalBridge {
    Principal resolve(OAuth2UserIdentity identity);
}
