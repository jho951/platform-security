package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.session.SecureRandomSessionIdGenerator;
import com.auth.session.SessionIdGenerator;
import com.auth.session.SessionStore;

import java.util.Objects;

/**
 * 1계층 session store에 위임해 session을 발급하는 기본 구현이다.
 *
 * <p>로그인 성공 여부는 호출 서비스가 결정하고, 이 클래스는 이미 인증된 principal을
 * 저장 가능한 session으로 바꾸는 작업만 담당한다.</p>
 */
public final class DefaultSessionIssuanceCapability implements SessionIssuanceCapability {
    private final SessionStore sessionStore;
    private final SessionIdGenerator sessionIdGenerator;

    /**
     * secure random session id generator를 사용하는 issuer를 만든다.
     *
     * @param sessionStore 발급된 session을 저장할 1계층 store
     */
    public DefaultSessionIssuanceCapability(SessionStore sessionStore) {
        this(sessionStore, new SecureRandomSessionIdGenerator());
    }

    /**
     * session id 생성 전략을 명시해 issuer를 만든다.
     *
     * @param sessionStore 발급된 session을 저장할 1계층 store
     * @param sessionIdGenerator session id 생성기
     */
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
