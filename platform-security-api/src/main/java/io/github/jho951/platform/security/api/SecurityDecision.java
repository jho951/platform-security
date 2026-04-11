package io.github.jho951.platform.security.api;

public enum SecurityDecision {
    ALLOW,
    DENY;

    public boolean allowed() {
        return this == ALLOW;
    }
}
