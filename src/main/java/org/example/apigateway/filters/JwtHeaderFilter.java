package org.example.apigateway.filters;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;

/**
 * Фильтр gateway для проверки JWT токенов и добавления заголовков пользователя.
 * Этот фильтр извлекает JWT токен из заголовка Authorization, проверяет его
 * через сервис аутентификации и, в случае успеха, добавляет заголовки
 * X-User-Id и X-User-Role в запрос перед его передачей дальше.
 */
@Component
public class JwtHeaderFilter extends AbstractGatewayFilterFactory<JwtHeaderFilter.Config> {

    /**
     * URI для обращения к эндпоинту интроспекции токенов в SSO-сервисе.
     **/
    @Value("${const.auth.introspection-uri}")
    private String INTROSPECTION_URI;

    private static final Logger log = LoggerFactory.getLogger(JwtHeaderFilter.class);
        private final WebClient webClient;


        public JwtHeaderFilter(WebClient.Builder webClientBuilder) {
        super(Config.class);
        this.webClient = webClientBuilder.build();
    }

    /**
     * Применяет логику фильтра к текущему обмену (запрос/ответ).
     * <p>
     * Логика работы:
     * 1. Извлекает заголовок Authorization.
     * 2. Если заголовок отсутствует или не начинается с "Bearer ", возвращает 401 Unauthorized.
     * 3. Извлекает токен.
     * 4. Отправляет токен на эндпоинт интроспекции SSO-сервиса.
     * 5. Если токен активен:
     *    - Добавляет заголовки X-User-Id (ref_id или "MANAGER") и X-User-Role.
     *    - Передает запрос дальше по цепочке.
     * 6. Если токен неактивен или произошла ошибка при интроспекции, возвращает 401 Unauthorized.
     * </p>
     * @param config конфигурация фильтра (в данном случае не используется).
     * @return GatewayFilter, который будет применен к запросу.
     */
    @Override
    public GatewayFilter apply(Config config) {

        return (exchange, chain) -> {
            log.info("Entering JwtHeaderFilter for path: {}", exchange.getRequest().getPath());
            String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            String token = authHeader.replace("Bearer ", "");

            log.info(token);

            return webClient.post()
                    .uri(INTROSPECTION_URI)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("token", token))
                    .retrieve()
                    .bodyToMono(Map.class)
                    .flatMap(response -> {
                        log.info(response.toString());
                        if (Boolean.TRUE.equals(response.get("active"))) {
                            log.info("Active");
                            var modifiedRequest = exchange.getRequest()
                                    .mutate()
                                    .header("X-User-Id", response.get("ref_id") != null ?
                                            response.get("ref_id").toString() : "MANAGER")
                                    .header("X-User-Role", response.get("role").toString())
                                    .build();
                            return chain.filter(exchange.mutate().request(modifiedRequest).build());
                        }
                        log.info("Inactive");
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    })
                    .onErrorResume(e -> {
                        log.info(e.toString()); // Логируем ошибку интроспекции
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    });
        };
    }

    /**
     * Класс конфигурации для JwtHeaderFilter.
     * В данном случае не содержит свойств, но необходим для AbstractGatewayFilterFactory.
     */
    public static class Config {
        // Add configuration properties here if needed
    }
}