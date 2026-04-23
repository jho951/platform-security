package io.github.jho951.platform.security.web;

import org.springframework.core.Ordered;

import java.util.Map;

/**
 * inbound header나 gateway metadata를 platform attribute로 확장하는 공식 ingress SPI다.
 */
public interface SecurityRequestAttributeContributor extends Ordered {
    /**
     * ingress context를 읽고 request attribute를 추가한다.
     *
     * @param context 정규화 중인 ingress context
     * @param attributes 수정 가능한 attribute map
     */
    void contribute(SecurityIngressContext context, Map<String, String> attributes);

    @Override
    default int getOrder() {
        return 0;
    }
}
