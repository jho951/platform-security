package io.github.jho951.platform.security.governance;

import io.github.jho951.platform.governance.api.AuditEntry;
import io.github.jho951.platform.security.api.ResolvedSecurityProfile;
import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityEvaluationContext;
import io.github.jho951.platform.security.api.SecurityEvaluationResult;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class GovernanceSecurityAuditPublisherTest {
    @Test
    void recordsSecurityEvaluationAsGovernanceAuditEntry() {
        List<AuditEntry> entries = new ArrayList<>();
        GovernanceSecurityAuditPublisher publisher = new GovernanceSecurityAuditPublisher(entries::add);

        publisher.publish(new SecurityEvaluationResult(
                new SecurityEvaluationContext(
                        new SecurityRequest(null, "10.0.0.10", "/api/orders", "GET", Map.of(), Instant.parse("2026-01-01T00:00:00Z")),
                        new SecurityContext(true, "user-1", Set.of("USER"), Map.of()),
                        new ResolvedSecurityProfile("PROTECTED", List.of("/api/**"), "EXTERNAL_API", "JWT")
                ),
                SecurityVerdict.allow("auth", "authenticated")
        ));

        assertThat(entries).hasSize(1);
        AuditEntry entry = entries.get(0);
        assertThat(entry.category()).isEqualTo("security");
        assertThat(entry.attributes()).containsEntry("security.allowed", "true");
        assertThat(entry.attributes()).containsEntry("security.boundary", "PROTECTED");
        assertThat(entry.attributes()).containsEntry("security.principal", "user-1");
    }
}
