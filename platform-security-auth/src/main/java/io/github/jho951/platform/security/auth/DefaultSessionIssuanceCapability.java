package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.session.SecureRandomSessionIdGenerator;
import com.auth.session.SessionIdGenerator;
import com.auth.session.SessionStore;

import java.util.Objects;

public final class DefaultSessionIssuanceCapability implements SessionIssuanceCapability {
    private final SessionStore sessionStore;
    private final SessionIdGenerator sessionIdGenerator;

    public DefaultSessionIssuanceCapability(SessionStore sessionStore) {
        this(sessionStore, new SecureRandomSessionIdGenerator());
    }

    public DefaultSessionIssuanceCapability(SessionStore sessionStore, SessionIdGenerator sessionIdGenerator) {
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
