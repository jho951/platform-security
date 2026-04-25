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
 * <p>운영 issuer 서비스는 {@code PlatformTokenIssuerPort}, {@code PlatformSessionIssuerPort}를
 * 직접 제공하거나 optional auth bridge starter가 raw auth bean을 이 port로 감싼 결과를 제공한다.
 * 이 자동 구성은 준비된 platform port를 issuance capability로 연결만 한다.</p>
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
