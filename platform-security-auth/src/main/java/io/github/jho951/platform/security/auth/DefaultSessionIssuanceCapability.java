package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;

import java.util.Objects;

/**
 * 1계층 session store에 위임해 session을 발급하는 기본 구현이다.
 *
 * <p>로그인 성공 여부는 호출 서비스가 결정하고, 이 클래스는 이미 인증된 principal을
 * 저장 가능한 session으로 바꾸는 작업만 담당한다.</p>
 */
public final class DefaultSessionIssuanceCapability implements SessionIssuanceCapability {
    private final PlatformSessionIssuerPort sessionIssuerPort;

    /**
     * @param sessionIssuerPort session 발급 port
     */
    public DefaultSessionIssuanceCapability(PlatformSessionIssuerPort sessionIssuerPort) {
        this.sessionIssuerPort = Objects.requireNonNull(sessionIssuerPort, "sessionIssuerPort");
    }

    @Override
    public String issueSession(Principal principal) {
        Objects.requireNonNull(principal, "principal");
        return sessionIssuerPort.issueSession(principal);
    }
}
