package io.github.jho951.platform.security.auth;

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
    public PlatformSessionView issueSession(PlatformIssueSessionCommand command) {
        Objects.requireNonNull(command, "command");
        String sessionId = sessionIdGenerator.generate();
        PlatformAuthenticatedPrincipal principal = command.principal();
        sessionStore.save(sessionId, AuthPrincipalAdapters.toAuth(principal));
        return new PlatformSessionView(sessionId, principal);
    }
}
