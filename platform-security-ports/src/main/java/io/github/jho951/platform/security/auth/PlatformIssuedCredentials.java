package io.github.jho951.platform.security.auth;

/**
 * hybrid 발급 결과를 담는 runtime view다.
 */
public record PlatformIssuedCredentials(
        PlatformIssuedToken token,
        PlatformSessionView session
) {
}
