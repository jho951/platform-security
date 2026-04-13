package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.apikey.ApiKeyAuthenticationProvider;
import com.auth.apikey.ApiKeyCredential;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * API key credential을 처리하는 platform capability다.
 *
 * <p>이 capability는 request attributes를 {@link ApiKeyCredential}로 변환하는
 * 역할만 한다. key 조회, secret 비교, rotation 정책, principal 생성은 설정된
 * {@link ApiKeyAuthenticationProvider}에 위임한다.</p>
 */
public final class DefaultApiKeyAuthenticationCapability implements AuthenticationCapability {
    private final ApiKeyAuthenticationProvider apiKeyAuthenticationProvider;

    /**
     * API key 검증을 수행할 1계층 provider와 capability를 연결한다.
     *
     * @param apiKeyAuthenticationProvider key 조회와 검증을 담당하는 provider
     */
    public DefaultApiKeyAuthenticationCapability(ApiKeyAuthenticationProvider apiKeyAuthenticationProvider) {
        this.apiKeyAuthenticationProvider = Objects.requireNonNull(apiKeyAuthenticationProvider, "apiKeyAuthenticationProvider");
    }

    @Override
    public String name() {
        return "api-key";
    }

    @Override
    public Optional<Principal> authenticate(SecurityRequest request) {
        Map<String, String> attributes = request.attributes();
        String keyId = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.API_KEY_ID_ATTRIBUTE));
        String secret = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.API_KEY_SECRET_ATTRIBUTE));
        if (keyId == null || secret == null) {
            return Optional.empty();
        }
        return apiKeyAuthenticationProvider.authenticate(new ApiKeyCredential(keyId, secret));
    }
}
