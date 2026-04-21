package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.session.SecureRandomSessionIdGenerator;
import com.auth.session.SessionIdGenerator;
import com.auth.session.SessionStore;

import java.util.Objects;

/**
 * 1계층 SessionStore를 platform session issuer port로 감싼다.
 */
public final class SessionStorePlatformSessionIssuerPort implements PlatformSessionIssuerPort {
    private final SessionStore sessionStore;
    private final SessionIdGenerator sessionIdGenerator;

    public SessionStorePlatformSessionIssuerPort(SessionStore sessionStore) {
        this(sessionStore, new SecureRandomSessionIdGenerator());
    }

    public SessionStorePlatformSessionIssuerPort(
            SessionStore sessionStore,
            SessionIdGenerator sessionIdGenerator
    ) {
        this.sessionStore = Objects.requireNonNull(sessionStore, "sessionStore");
        this.sessionIdGenerator = Objects.requireNonNull(sessionIdGenerator, "sessionIdGenerator");
    }

    @Override
    public String issueSession(Principal principal) {
        Objects.requireNonNull(principal, "principal");
        String sessionId = sessionIdGenerator.generate();
        sessionStore.save(sessionId, principal);
        return sessionId;
    }
}
