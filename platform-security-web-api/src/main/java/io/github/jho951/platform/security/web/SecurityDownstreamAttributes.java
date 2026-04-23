package io.github.jho951.platform.security.web;

/**
 * servlet/reactive request에 저장되는 downstream security attribute key 모음이다.
 */
public final class SecurityDownstreamAttributes {
    public static final String ATTR_DOWNSTREAM_HEADERS = "security.downstream.headers";

    private SecurityDownstreamAttributes() {
    }
}
