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

@Component
public class JwtHeaderFilter extends AbstractGatewayFilterFactory<JwtHeaderFilter.Config> {

    @Value("${const.auth.introspection-uri}")
    private String INTROSPECTION_URI;

    private static final Logger log = LoggerFactory.getLogger(JwtHeaderFilter.class);
    private final WebClient webClient;


    public JwtHeaderFilter(WebClient.Builder webClientBuilder) {
        super(Config.class);
        this.webClient = webClientBuilder.build();
    }

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
                        log.info(e.toString());
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    });
        };
    }

    public static class Config {
        // Add configuration properties here if needed
    }
}