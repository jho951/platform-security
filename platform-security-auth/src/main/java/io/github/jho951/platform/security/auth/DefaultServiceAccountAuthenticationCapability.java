package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.serviceaccount.ServiceAccountAuthenticationProvider;
import com.auth.serviceaccount.ServiceAccountCredential;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * service account credential을 처리하는 platform capability다.
 *
 * <p>platform 계층은 request attributes에서 service id와 secret을 추출한다.
 * 검증, credential lifecycle, service ownership 정책은 설정된
 * {@link ServiceAccountAuthenticationProvider}에 위임한다.</p>
 */
public final class DefaultServiceAccountAuthenticationCapability implements AuthenticationCapability {
    private final ServiceAccountAuthenticationProvider serviceAccountAuthenticationProvider;

    /**
     * service account 검증을 수행할 1계층 provider와 capability를 연결한다.
     *
     * @param serviceAccountAuthenticationProvider service account credential 검증 provider
     */
    public DefaultServiceAccountAuthenticationCapability(ServiceAccountAuthenticationProvider serviceAccountAuthenticationProvider) {
        this.serviceAccountAuthenticationProvider = Objects.requireNonNull(serviceAccountAuthenticationProvider, "serviceAccountAuthenticationProvider");
    }

    @Override
    public String name() {
        return "service-account";
    }

    @Override
    public Optional<Principal> authenticate(SecurityRequest request) {
        Map<String, String> attributes = request.attributes();
        String serviceId = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.SERVICE_ACCOUNT_ID_ATTRIBUTE));
        String secret = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.SERVICE_ACCOUNT_SECRET_ATTRIBUTE));
        if (serviceId == null || secret == null) {
            return Optional.empty();
        }
        return serviceAccountAuthenticationProvider.authenticate(new ServiceAccountCredential(serviceId, secret));
    }
}
