package io.github.jho951.platform.security.starter;

/**
 * Marker type for the platform-security starter artifact.
 *
 * <p>The starter intentionally contains no runtime logic. Spring Boot wiring
 * lives in platform-security-autoconfigure, and this module only gives
 * services a single dependency entry point.</p>
 */
public final class PlatformSecurityStarter {
    public static final String ARTIFACT_ID = "platform-security-starter";

    private PlatformSecurityStarter() {
    }
}
