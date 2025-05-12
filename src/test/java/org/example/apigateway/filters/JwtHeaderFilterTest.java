package org.example.apigateway.filters;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Тесты для {@link JwtHeaderFilter}.
 * Проверяют корректность работы фильтра в различных сценариях.
 */
@ExtendWith(MockitoExtension.class)
class JwtHeaderFilterTest {

    private static final String INTROSPECTION_URI = "http://sso-service/auth/introspection";
    private static final String VALID_TOKEN = "valid.jwt.token";
    private static final String INVALID_TOKEN = "invalid.jwt.token";
    private static final String REF_ID = "42";
    private static final String ROLE = "ROLE_SUBSCRIBER";

    @Mock
    private WebClient.Builder webClientBuilder;
    
    @Mock
    private WebClient webClient;

    @Mock
    private GatewayFilterChain filterChain;

    private JwtHeaderFilter jwtHeaderFilter;

    @BeforeEach
    void setUp() {
        when(webClientBuilder.build()).thenReturn(webClient);
        
        jwtHeaderFilter = new JwtHeaderFilter(webClientBuilder);
        ReflectionTestUtils.setField(jwtHeaderFilter, "INTROSPECTION_URI", INTROSPECTION_URI);
        ReflectionTestUtils.setField(jwtHeaderFilter, "webClient", webClient);
    }

    /**
     * Тест: если заголовок Authorization отсутствует, должен вернуться статус UNAUTHORIZED.
     */
    @Test
    void apply_WithNoAuthHeader_ReturnsUnauthorized() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        
        GatewayFilter filter = jwtHeaderFilter.apply(new JwtHeaderFilter.Config());
        Mono<Void> result = filter.filter(exchange, filterChain);
        
        StepVerifier.create(result)
                .expectComplete()
                .verify();
        
        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        verifyNoInteractions(filterChain);
    }

    /**
     * Тест: если формат заголовка Authorization некорректен, должен вернуться статус UNAUTHORIZED.
     */
    @Test
    void apply_WithInvalidAuthHeaderFormat_ReturnsUnauthorized() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .header(HttpHeaders.AUTHORIZATION, "InvalidFormat " + VALID_TOKEN)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        
        GatewayFilter filter = jwtHeaderFilter.apply(new JwtHeaderFilter.Config());
        Mono<Void> result = filter.filter(exchange, filterChain);
        
        StepVerifier.create(result)
                .expectComplete()
                .verify();
        
        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        verifyNoInteractions(filterChain);
    }

    /**
     * Тест: если токен валиден, должны быть добавлены заголовки X-User-Id и X-User-Role,
     * и запрос должен быть передан дальше по цепочке.
     */
    @Test
    void apply_WithValidToken_AddsUserHeaders() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + VALID_TOKEN)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        
        WebClient.RequestBodyUriSpec requestBodyUriSpec = mock(WebClient.RequestBodyUriSpec.class);
        WebClient.RequestBodySpec requestBodySpec = mock(WebClient.RequestBodySpec.class);
        WebClient.RequestHeadersSpec requestHeadersSpec = mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec responseSpec = mock(WebClient.ResponseSpec.class);
        
        when(webClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(INTROSPECTION_URI)).thenReturn(requestBodySpec);
        when(requestBodySpec.contentType(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpec);
        when(requestBodySpec.bodyValue(any(Map.class))).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        
        Map<String, Object> tokenResponse = Map.of(
                "active", true,
                "ref_id", REF_ID,
                "role", ROLE
        );
        
        when(responseSpec.bodyToMono(Map.class)).thenReturn(Mono.just(tokenResponse));
        
        ArgumentCaptor<ServerWebExchange> exchangeCaptor = ArgumentCaptor.forClass(ServerWebExchange.class);
        when(filterChain.filter(exchangeCaptor.capture())).thenReturn(Mono.empty());
        
        GatewayFilter filter = jwtHeaderFilter.apply(new JwtHeaderFilter.Config());
        Mono<Void> result = filter.filter(exchange, filterChain);
        
        StepVerifier.create(result)
                .expectComplete()
                .verify();
        
        ServerWebExchange capturedExchange = exchangeCaptor.getValue();
        assertNotNull(capturedExchange);
        assertEquals(REF_ID, capturedExchange.getRequest().getHeaders().getFirst("X-User-Id"));
        assertEquals(ROLE, capturedExchange.getRequest().getHeaders().getFirst("X-User-Role"));
        
        verify(requestBodySpec).bodyValue(Map.of("token", VALID_TOKEN));
    }

    /**
     * Тест: если сервис интроспекции возвращает, что токен неактивен,
     * должен вернуться статус UNAUTHORIZED.
     */
    @Test
    void apply_WithInactiveToken_ReturnsUnauthorized() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + INVALID_TOKEN)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        
        WebClient.RequestBodyUriSpec requestBodyUriSpec = mock(WebClient.RequestBodyUriSpec.class);
        WebClient.RequestBodySpec requestBodySpec = mock(WebClient.RequestBodySpec.class);
        WebClient.RequestHeadersSpec requestHeadersSpec = mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec responseSpec = mock(WebClient.ResponseSpec.class);
        
        when(webClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(INTROSPECTION_URI)).thenReturn(requestBodySpec);
        when(requestBodySpec.contentType(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpec);
        when(requestBodySpec.bodyValue(any(Map.class))).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        
        Map<String, Object> tokenResponse = Map.of(
                "active", false
        );
        
        when(responseSpec.bodyToMono(Map.class)).thenReturn(Mono.just(tokenResponse));
        
        GatewayFilter filter = jwtHeaderFilter.apply(new JwtHeaderFilter.Config());
        Mono<Void> result = filter.filter(exchange, filterChain);
        
        StepVerifier.create(result)
                .expectComplete()
                .verify();
        
        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        verifyNoInteractions(filterChain);
    }

    /**
     * Тест: если при обращении к сервису интроспекции происходит ошибка,
     * должен вернуться статус UNAUTHORIZED.
     */
    @Test
    void apply_WithIntrospectionError_ReturnsUnauthorized() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + VALID_TOKEN)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        
        WebClient.RequestBodyUriSpec requestBodyUriSpec = mock(WebClient.RequestBodyUriSpec.class);
        WebClient.RequestBodySpec requestBodySpec = mock(WebClient.RequestBodySpec.class);
        WebClient.RequestHeadersSpec requestHeadersSpec = mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec responseSpec = mock(WebClient.ResponseSpec.class);
        
        when(webClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(INTROSPECTION_URI)).thenReturn(requestBodySpec);
        when(requestBodySpec.contentType(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpec);
        when(requestBodySpec.bodyValue(any(Map.class))).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        
        when(responseSpec.bodyToMono(Map.class)).thenReturn(Mono.error(new RuntimeException("Service unavailable")));
        
        GatewayFilter filter = jwtHeaderFilter.apply(new JwtHeaderFilter.Config());
        Mono<Void> result = filter.filter(exchange, filterChain);
        
        StepVerifier.create(result)
                .expectComplete()
                .verify();
        
        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        verifyNoInteractions(filterChain);
    }

    /**
     * Тест: если токен валиден, но ref_id отсутствует в ответе от сервиса интроспекции,
     * в заголовок X-User-Id должно быть установлено значение "MANAGER".
     */
    @Test
    void apply_WithNullRefId_UsesManager() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + VALID_TOKEN)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        
        WebClient.RequestBodyUriSpec requestBodyUriSpec = mock(WebClient.RequestBodyUriSpec.class);
        WebClient.RequestBodySpec requestBodySpec = mock(WebClient.RequestBodySpec.class);
        WebClient.RequestHeadersSpec requestHeadersSpec = mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec responseSpec = mock(WebClient.ResponseSpec.class);
        
        when(webClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri(INTROSPECTION_URI)).thenReturn(requestBodySpec);
        when(requestBodySpec.contentType(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpec);
        when(requestBodySpec.bodyValue(any(Map.class))).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        
        Map<String, Object> tokenResponse = Map.of(
                "active", true,
                "role", ROLE
        );
        
        when(responseSpec.bodyToMono(Map.class)).thenReturn(Mono.just(tokenResponse));
        
        ArgumentCaptor<ServerWebExchange> exchangeCaptor = ArgumentCaptor.forClass(ServerWebExchange.class);
        when(filterChain.filter(exchangeCaptor.capture())).thenReturn(Mono.empty());
        
        GatewayFilter filter = jwtHeaderFilter.apply(new JwtHeaderFilter.Config());
        Mono<Void> result = filter.filter(exchange, filterChain);
        
        StepVerifier.create(result)
                .expectComplete()
                .verify();
        
        ServerWebExchange capturedExchange = exchangeCaptor.getValue();
        assertNotNull(capturedExchange);
        assertEquals("MANAGER", capturedExchange.getRequest().getHeaders().getFirst("X-User-Id"));
        assertEquals(ROLE, capturedExchange.getRequest().getHeaders().getFirst("X-User-Role"));
    }
}
