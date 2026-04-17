package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Optional;

/**
 * platform {@link SecurityRequest}와 auth 1계층의 실제 인증 구현 사이를 잇는 작은 adapter다.
 * <p>
 * 구현체는 request attributes를 하위 provider가 기대하는 credential 객체로 변환하는 데 집중한다.
 * 서비스별 user provisioning, tenant mapping, 권한 정책은 넣지 않는다.
 * </p>
 */
public interface AuthenticationCapability {
    /**
     * 진단과 테스트에 쓰는 안정적인 capability 이름이다.
     * @return capability 이름
     */
    String name();

    /**
     * 요청 인증을 시도한다.
     * @param request 인증 credential이 담긴 platform 요청
     * @return credential이 존재하고 유효하면 principal, 아니면 empty
     */
    Optional<Principal> authenticate(SecurityRequest request);
}
