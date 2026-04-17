package io.github.jho951.platform.security.starter;

/**
 * platform-security 기본 starter artifact를 표시하는 marker 타입이다.
 *
 * <p>starter 자체에는 runtime logic을 넣지 않는다. Spring Boot 조립은
 * platform-security-autoconfigure가 담당하고, 이 모듈은 서비스가 의존할 단일 진입점을 제공한다.</p>
 */
public final class PlatformSecurityStarter {
    public static final String ARTIFACT_ID = "platform-security-starter";

    private PlatformSecurityStarter() {
    }
}
