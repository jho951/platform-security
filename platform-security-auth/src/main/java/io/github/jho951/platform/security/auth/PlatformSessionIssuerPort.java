package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;

/**
 * issuer 서비스가 browser session을 발급할 때 사용하는 port다.
 */
public interface PlatformSessionIssuerPort {

    String issueSession(Principal principal);
}
