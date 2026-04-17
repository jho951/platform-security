package io.github.jho951.platform.security.policy;

/**
 * role starter가 auto-configuration에 자신의 preset을 전달하는 SPI다.
 */
@FunctionalInterface
public interface ServiceRolePresetProvider {
    /**
     * @return starter가 요구하는 service role preset
     */
    ServiceRolePreset serviceRolePreset();
}
