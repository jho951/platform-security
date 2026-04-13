package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;

import java.util.Objects;

public final class HybridIssuanceCapability implements TokenIssuanceCapability {
    private final TokenIssuanceCapability tokenIssuanceCapability;
    private final SessionIssuanceCapability sessionIssuanceCapability;

    public HybridIssuanceCapability(
            TokenIssuanceCapability tokenIssuanceCapability,
            SessionIssuanceCapability sessionIssuanceCapability
    ) {
        this.tokenIssuanceCapability = Objects.requireNonNull(tokenIssuanceCapability, "tokenIssuanceCapability");
        this.sessionIssuanceCapability = Objects.requireNonNull(sessionIssuanceCapability, "sessionIssuanceCapability");
    }

    @Override
    public PlatformTokenBundle issue(Principal principal) {
        PlatformTokenBundle tokens = tokenIssuanceCapability.issue(principal);
        return new PlatformTokenBundle(
                tokens.accessToken(),
                tokens.refreshToken(),
                sessionIssuanceCapability.issueSession(principal)
        );
    }
}
