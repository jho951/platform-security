package io.github.jho951.platform.security.governance;

import io.github.jho951.platform.governance.api.AuditLogRecorder;
import io.github.jho951.platform.security.web.SecurityAuditPublisher;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * governance audit recorder가 있을 때 security audit publisher를 자동 연결한다.
 */
@AutoConfiguration
@AutoConfigureAfter(name = "io.github.jho951.platform.governance.spring.PlatformGovernanceAutoConfiguration")
@AutoConfigureBefore(name = "io.github.jho951.platform.security.autoconfigure.PlatformSecurityAutoConfiguration")
@ConditionalOnClass({AuditLogRecorder.class, SecurityAuditPublisher.class})
public class PlatformSecurityGovernanceBridgeAutoConfiguration {
    @Bean
    @ConditionalOnBean(AuditLogRecorder.class)
    @ConditionalOnMissingBean(SecurityAuditPublisher.class)
    public SecurityAuditPublisher governanceSecurityAuditPublisher(AuditLogRecorder auditLogRecorder) {
        return new GovernanceSecurityAuditPublisher(auditLogRecorder);
    }
}
