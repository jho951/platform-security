package io.github.jho951.platform.security.auth;

import java.util.Objects;

/**
 * session 발급에 필요한 runtime 입력이다.
 */
public record PlatformIssueSessionCommand(
        PlatformAuthenticatedPrincipal principal
) {
    public PlatformIssueSessionCommand {
        principal = Objects.requireNonNull(principal, "principal");
    }
}
