package io.github.jho951.platform.security.auth;

public final class AuthServerHeaderNames {
    public static final String AUTHORIZATION = "Authorization";
    public static final String AUTHENTICATED = "X-Auth-Authenticated";
    public static final String PRINCIPAL = "X-Auth-Principal";
    public static final String ROLES = "X-Auth-Roles";
    public static final String SESSION_ID = "X-Auth-Session-Id";
    public static final String ACCESS_TOKEN_ATTRIBUTE = "auth.accessToken";
    public static final String SESSION_ID_ATTRIBUTE = "auth.sessionId";

    private AuthServerHeaderNames() {
    }
}
