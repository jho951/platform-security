package io.github.jho951.platform.security.client;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

/**
 * Feign이 classpath에 있을 때 RequestInterceptor proxy를 만든다.
 */
public final class SecurityFeignRequestInterceptorFactory {
    private SecurityFeignRequestInterceptorFactory() {
    }

    public static Object create() {
        try {
            Class<?> interceptorType = Class.forName("feign.RequestInterceptor");
            return Proxy.newProxyInstance(
                    interceptorType.getClassLoader(),
                    new Class<?>[]{interceptorType},
                    (proxy, method, args) -> {
                        if ("apply".equals(method.getName()) && args != null && args.length == 1 && args[0] != null) {
                            applyHeaders(args[0]);
                        }
                        return defaultValue(method.getReturnType());
                    }
            );
        } catch (ClassNotFoundException ex) {
            throw new IllegalStateException("Feign RequestInterceptor is not on the classpath", ex);
        }
    }

    private static void applyHeaders(Object requestTemplate) throws Exception {
        Method header = requestTemplate.getClass().getMethod("header", String.class, String[].class);
        for (var entry : SecurityOutboundContextHolder.currentHeaders().entrySet()) {
            header.invoke(requestTemplate, entry.getKey(), (Object) new String[]{entry.getValue()});
        }
    }

    private static Object defaultValue(Class<?> returnType) {
        if (returnType == Void.TYPE) {
            return null;
        }
        if (returnType == Boolean.TYPE) {
            return false;
        }
        if (returnType == Byte.TYPE || returnType == Short.TYPE || returnType == Integer.TYPE || returnType == Long.TYPE) {
            return 0;
        }
        if (returnType == Float.TYPE || returnType == Double.TYPE) {
            return 0.0;
        }
        if (returnType == Character.TYPE) {
            return '\0';
        }
        return null;
    }
}
