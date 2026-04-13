package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;

public interface TokenIssuanceCapability {
    PlatformTokenBundle issue(Principal principal);
}
