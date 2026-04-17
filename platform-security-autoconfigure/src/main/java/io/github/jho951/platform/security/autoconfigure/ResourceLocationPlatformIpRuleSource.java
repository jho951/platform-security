package io.github.jho951.platform.security.autoconfigure;

import io.github.jho951.platform.security.ip.PlatformIpRuleSource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Spring resource location에서 IP guard rule 파일을 읽는 source다.
 */
public final class ResourceLocationPlatformIpRuleSource implements PlatformIpRuleSource {
    private final ResourceLoader resourceLoader;
    private final String location;

    /**
     * @param resourceLoader Spring resource loader
     * @param location rule file location
     */
    public ResourceLocationPlatformIpRuleSource(ResourceLoader resourceLoader, String location) {
        this.resourceLoader = Objects.requireNonNull(resourceLoader, "resourceLoader");
        this.location = Objects.requireNonNull(location, "location");
    }

    @Override
    public String loadRules() {
        Resource resource = resourceLoader.getResource(location);
        if (!resource.exists() || !resource.isReadable()) {
            throw new IllegalStateException("IP rules resource is not readable: " + location);
        }

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8)
        )) {
            return reader.lines()
                    .map(String::trim)
                    .filter(line -> !line.isBlank())
                    .filter(line -> !line.startsWith("#"))
                    .collect(Collectors.joining("\n"));
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to read IP rules resource: " + location, ex);
        }
    }
}
