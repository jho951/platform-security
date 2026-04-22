package io.github.jho951.platform.security.auth;

import java.util.Objects;

/**
 * token 발급에 필요한 runtime 입력이다.
 */
public record PlatformIssueTokenCommand(
        PlatformAuthenticatedPrincipal principal
) {
    public PlatformIssueTokenCommand {
        principal = Objects.requireNonNull(principal, "principal");
    }
}
