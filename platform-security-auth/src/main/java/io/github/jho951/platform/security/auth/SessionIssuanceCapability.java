package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;

public interface SessionIssuanceCapability {
    String issueSession(Principal principal);
}
