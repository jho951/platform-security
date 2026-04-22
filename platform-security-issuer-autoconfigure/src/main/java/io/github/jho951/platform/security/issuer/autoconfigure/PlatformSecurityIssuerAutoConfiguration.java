package io.github.jho951.platform.security.issuer.autoconfigure;

import io.github.jho951.platform.security.auth.DefaultSessionIssuanceCapability;
import io.github.jho951.platform.security.auth.DefaultTokenIssuanceCapability;
import io.github.jho951.platform.security.auth.PlatformSessionIssuerPort;
import io.github.jho951.platform.security.auth.PlatformTokenIssuerPort;
import io.github.jho951.platform.security.auth.SessionIssuanceCapability;
import io.github.jho951.platform.security.auth.TokenIssuanceCapability;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * issuer role에서만 필요한 token/session 발급 graph다.
 *
 * <p>운영 TokenService와 SessionStore는 3계층 issuer 서비스가 제공한다. 이 자동 구성은
 * 제공된 1계층 OSS bean을 issuance capability로 연결만 한다.</p>
 */
@AutoConfiguration
public class PlatformSecurityIssuerAutoConfiguration {
    @Bean
    @ConditionalOnBean(PlatformTokenIssuerPort.class)
    @ConditionalOnMissingBean(TokenIssuanceCapability.class)
    public TokenIssuanceCapability tokenIssuanceCapability(PlatformTokenIssuerPort tokenIssuerPort) {
        return new DefaultTokenIssuanceCapability(tokenIssuerPort);
    }

    @Bean
    @ConditionalOnBean(PlatformSessionIssuerPort.class)
    @ConditionalOnMissingBean(SessionIssuanceCapability.class)
    public SessionIssuanceCapability sessionIssuanceCapability(PlatformSessionIssuerPort sessionIssuerPort) {
        return new DefaultSessionIssuanceCapability(sessionIssuerPort);
    }
}
