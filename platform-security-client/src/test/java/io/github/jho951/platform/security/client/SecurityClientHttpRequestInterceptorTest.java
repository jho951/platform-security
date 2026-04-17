package io.github.jho951.platform.security.client;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.mock.http.client.MockClientHttpRequest;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SecurityClientHttpRequestInterceptorTest {
    @Test
    void appliesCurrentSecurityHeadersToRequest() throws Exception {
        SecurityOutboundContextHolder.set(Map.of("X-Security-Principal", "user-1"));
        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.GET, "/downstream");
        ClientHttpRequestExecution execution = (httpRequest, body) -> {
            HttpHeaders headers = httpRequest.getHeaders();
            assertEquals("user-1", headers.getFirst("X-Security-Principal"));
            return null;
        };

        new SecurityClientHttpRequestInterceptor().intercept(request, new byte[0], execution);

        SecurityOutboundContextHolder.clear();
    }
}
