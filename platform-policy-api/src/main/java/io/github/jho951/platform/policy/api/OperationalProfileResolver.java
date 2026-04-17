package io.github.jho951.platform.policy.api;

import java.util.Collection;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Resolves whether active runtime profiles should be treated as production.
 */
@FunctionalInterface
public interface OperationalProfileResolver {
    boolean isProduction(Collection<String> activeProfiles, Collection<String> productionProfiles);

    static OperationalProfileResolver standard() {
        return (activeProfiles, productionProfiles) -> {
            Set<String> normalizedProductionProfiles = normalize(productionProfiles);
            if (normalizedProductionProfiles.isEmpty()) {
                return false;
            }
            return normalize(activeProfiles).stream().anyMatch(normalizedProductionProfiles::contains);
        };
    }

    private static Set<String> normalize(Collection<String> values) {
        if (values == null) {
            return Set.of();
        }
        return values.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .map(value -> value.toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
    }
}
