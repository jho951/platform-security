package io.github.jho951.platform.security.ip;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * 하위 IP rule source의 결과를 TTL 동안 캐싱하는 rule source다.
 *
 * <p>{@code staleWhileError=true}이면 reload 실패 시 마지막 성공 rule을 계속 반환한다.</p>
 */
public final class CachingPlatformIpRuleSource implements PlatformIpRuleSource {
    private final PlatformIpRuleSource delegate;
    private final Duration ttl;
    private final boolean staleWhileError;

    private volatile String cachedRules = "";
    private volatile Instant loadedAt = Instant.EPOCH;
    private volatile boolean initialized = false;

    public CachingPlatformIpRuleSource(PlatformIpRuleSource delegate, Duration ttl, boolean staleWhileError) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.ttl = ttl == null ? Duration.ZERO : ttl;
        this.staleWhileError = staleWhileError;
    }

    @Override
    public String loadRules() {
        Instant now = Instant.now();
        if (initialized && !ttl.isNegative() && now.isBefore(loadedAt.plus(ttl))) {
            return cachedRules;
        }

        try {
            String loaded = delegate.loadRules();
            cachedRules = loaded == null ? "" : loaded;
            loadedAt = now;
            initialized = true;
            return cachedRules;
        } catch (RuntimeException ex) {
            if (initialized && staleWhileError) {
                return cachedRules;
            }
            throw ex;
        }
    }
}
