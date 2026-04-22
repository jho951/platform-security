package io.github.jho951.platform.security.auth;

/**
 * raw auth SPI 조립을 platform 소유 session support로 감싸는 factory다.
 */
@FunctionalInterface
public interface PlatformSessionSupportFactory {

    PlatformSessionSupport create();
}
