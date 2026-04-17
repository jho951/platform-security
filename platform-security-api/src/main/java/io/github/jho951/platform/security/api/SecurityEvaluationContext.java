package io.github.jho951.platform.security.api;

import java.util.Objects;

/**
 * 보안 평가에 전달되는 전체 입력 context다.
 *
 * @param request 평가 대상 정규화 요청
 * @param securityContext 해석된 인증 context
 * @param profile 해석된 boundary, client type, auth mode
 */
public record SecurityEvaluationContext(
        SecurityRequest request,
        SecurityContext securityContext,
        ResolvedSecurityProfile profile
) {
    public SecurityEvaluationContext {
        request = Objects.requireNonNull(request, "request");
        securityContext = Objects.requireNonNull(securityContext, "securityContext");
        profile = Objects.requireNonNull(profile, "profile");
    }
}
