package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.oidc.OidcIdentity;
import com.auth.oidc.OidcPrincipalMapper;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * 검증된 OIDC identity를 공통 {@link Principal} 모델로 바꾸는 설정 기반 mapper다.
 *
 * <p>이 클래스는 id_token을 검증하지 않는다. 검증은 1계층 구현 또는 소비 서비스가
 * 제공하는 {@link com.auth.oidc.OidcTokenVerifier} bean이 담당한다. 이 mapper는
 * {@link PlatformSecurityProperties.OidcProperties}에 따라 claims를 기계적으로
 * 읽기만 한다.</p>
 */
public final class DefaultOidcPrincipalMapper implements OidcPrincipalMapper {
    private final PlatformSecurityProperties.OidcProperties properties;

    /**
     * OIDC claim mapping 설정으로 mapper를 만든다.
     *
     * @param properties principal claim, authority claim, 기본 authority 설정
     */
    public DefaultOidcPrincipalMapper(PlatformSecurityProperties.OidcProperties properties) {
        this.properties = properties == null ? new PlatformSecurityProperties.OidcProperties() : properties;
    }

    /**
     * 검증된 OIDC identity를 principal로 변환한다.
     *
     * <p>principal id는 {@code principalClaim}에서 읽고, 없으면 OIDC subject를
     * 사용한다. authorities는 {@code authoritiesClaim}에서 읽은 값과 설정된 기본
     * authorities를 합쳐 만든다.</p>
     *
     * @param identity 1계층 verifier가 검증한 OIDC identity
     * @return platform 공통 principal
     */
    @Override
    public Principal map(OidcIdentity identity) {
        Objects.requireNonNull(identity, "identity");
        Map<String, Object> claims = identity.claims() == null ? Map.of() : identity.claims();
        String principal = claimAsString(claims.get(properties.getPrincipalClaim()));
        if (principal == null) {
            principal = identity.subject();
        }
        Map<String, Object> attributes = new LinkedHashMap<>(claims);
        attributes.putIfAbsent("issuer", identity.issuer());
        attributes.putIfAbsent("audience", identity.audience());
        return new Principal(principal, authorities(claims), attributes);
    }

    private List<String> authorities(Map<String, Object> claims) {
        List<String> authorities = new ArrayList<>();
        Object value = claims.get(properties.getAuthoritiesClaim());
        if (value instanceof Collection<?> collection) {
            collection.forEach(item -> addAuthority(authorities, item));
        } else if (value instanceof String string) {
            for (String item : string.split(",")) {
                addAuthority(authorities, item);
            }
        }
        properties.getDefaultAuthorities().forEach(item -> addAuthority(authorities, item));
        return List.copyOf(authorities);
    }

    private void addAuthority(List<String> authorities, Object value) {
        String authority = claimAsString(value);
        if (authority == null) {
            return;
        }
        String prefixed = properties.getAuthorityPrefix() + authority;
        if (!authorities.contains(prefixed)) {
            authorities.add(prefixed);
        }
    }

    private String claimAsString(Object value) {
        if (value == null) {
            return null;
        }
        String string = String.valueOf(value).trim();
        return string.isEmpty() ? null : string;
    }
}
