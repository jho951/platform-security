package io.github.jho951.platform.security.client;

import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import java.io.IOException;

/**
 * RestTemplate 및 RestClient outbound 요청에 security propagation header를 붙인다.
 */
public final class SecurityClientHttpRequestInterceptor implements ClientHttpRequestInterceptor {
    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        SecurityOutboundContextHolder.currentHeaders()
                .forEach((name, value) -> request.getHeaders().set(name, value));
        return execution.execute(request, body);
    }
}
