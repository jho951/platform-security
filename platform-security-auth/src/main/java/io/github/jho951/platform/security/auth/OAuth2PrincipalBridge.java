package io.github.jho951.platform.security.auth;

import com.auth.api.model.OAuth2UserIdentity;
import com.auth.api.model.Principal;

/**
 * 서비스가 소유한 OAuth2 로그인 결과를 공통 auth {@link Principal} 모델로 변환한다.
 *
 * <p>이 bridge는 provider별 OAuth2 flow가 끝난 뒤에 사용한다. redirect 처리,
 * authorization code exchange, user provisioning, 계정 연결, cookie 정책은
 * 계속 서비스 책임이다.</p>
 */
public interface OAuth2PrincipalBridge {
    /**
     * 검증된 provider identity를 platform principal로 변환한다.
     *
     * @param identity OAuth2 provider flow가 검증한 사용자 identity
     * @return platform 공통 principal
     */
    Principal resolve(OAuth2UserIdentity identity);
}
