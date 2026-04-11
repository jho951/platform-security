package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Optional;

public interface AuthenticationCapability {
    String name();

    Optional<Principal> authenticate(SecurityRequest request);
}
