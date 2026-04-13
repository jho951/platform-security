package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import io.github.jho951.platform.security.api.SecurityRequest;

/**
 * internal token 인증 이후 claim을 서비스 기준으로 추가 검증하는 hook이다.
 *
 * <p>조직별 issuer, audience, service id, environment 검증이 필요할 때 사용한다.
 * platform 계층은 서비스별 계약을 알 수 없으므로 기본 구현은 non-null principal을
 * 허용한다.</p>
 */
@FunctionalInterface
public interface InternalTokenClaimsValidator {
    /**
     * internal token 인증 결과가 현재 요청에서 허용 가능한지 판단한다.
     *
     * @param principal 1계층 provider가 검증한 principal
     * @param request 현재 platform 요청
     * @return 추가 claim 조건을 만족하면 true
     */
    boolean validate(Principal principal, SecurityRequest request);

    /**
     * principal 존재 여부만 확인하는 기본 validator를 반환한다.
     *
     * @return non-null principal을 허용하는 validator
     */
    static InternalTokenClaimsValidator allowAll() {
        return (principal, request) -> principal != null;
    }
}
