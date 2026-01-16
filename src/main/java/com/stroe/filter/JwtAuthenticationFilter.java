package com.stroe.filter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import com.stroe.dto.AuthValidationResponse;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

     private final WebClient webClient;

    @Value("${auth.service.url}")
    private String authServiceUrl;

    @Override
public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

    // 🔥 ALLOW PREFLIGHT REQUESTS
    if (exchange.getRequest().getMethod() == HttpMethod.OPTIONS) {
        return chain.filter(exchange);
    }

    String path = exchange.getRequest().getURI().getPath();

    if (path.startsWith("/auth")) {
        return chain.filter(exchange);
    }

    String authHeader = exchange.getRequest()
            .getHeaders()
            .getFirst(HttpHeaders.AUTHORIZATION);

    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
        return unauthorized(exchange);
    }

    return webClient.post()
            .uri(authServiceUrl + "/auth/validate")
            .header(HttpHeaders.AUTHORIZATION, authHeader)
            .retrieve()
            .bodyToMono(AuthValidationResponse.class)
            .flatMap(resp -> {

                if (!resp.isValid()) {
                    return unauthorized(exchange);
                }

                ServerHttpRequest mutatedRequest =
                        exchange.getRequest().mutate()
                                .header("X-Username", resp.getUsername())
                                .header("X-Roles", String.join(",", resp.getRoles()))
                                .build();

                return chain.filter(exchange.mutate().request(mutatedRequest).build());
            })
            .onErrorResume(e -> unauthorized(exchange));
}



    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }
}
