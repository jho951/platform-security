package io.github.jho951.platform.security.auth;

/**
 * issuer 서비스가 platform token bundle을 발급할 때 사용하는 port다.
 */
public interface PlatformTokenIssuerPort {

    PlatformTokenBundle issue(PlatformAuthenticatedPrincipal principal);
}
