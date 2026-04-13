package io.github.jho951.platform.security.policy;

/**
 * 요청의 boundary와 client type을 해석한 뒤 선택되는 인증 capability다.
 *
 * <p>이 enum은 provider가 아니라 capability 기준으로 정의한다. 예를 들어
 * {@link #OIDC}는 요청을 OIDC 인증 capability로 라우팅한다는 뜻이다.
 * provider별 로그인, token exchange, 계정 연결, 도메인 권한 판단은 이 계층의
 * 책임이 아니다.</p>
 */
public enum AuthMode {
    /** 요청 인증을 실행하지 않는다. */
    NONE,

    /** 보통 Authorization header에서 추출한 access token으로 인증한다. */
    JWT,

    /** session id로 인증한다. */
    SESSION,

    /** hybrid provider를 통해 JWT와 session credential을 조합해 인증한다. */
    HYBRID,

    /** 외부 API client가 보낸 API key credential로 인증한다. */
    API_KEY,

    /** 서명된 요청 credential로 인증한다. */
    HMAC,

    /** 이 계층 밖에서 제공된 verifier를 통해 OIDC id_token으로 인증한다. */
    OIDC,

    /** service account credential로 machine client를 인증한다. */
    SERVICE_ACCOUNT
}
