package com.stroe.filter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
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

    String path = exchange.getRequest().getURI().getPath();

    // Allow auth APIs
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
            .exchangeToMono(response -> {

                log.info("Auth-service returned {}", response.statusCode());
                if (!response.statusCode().is2xxSuccessful()) {
                    log.error("Auth-service returned {}", response.statusCode());
                    return Mono.empty();
                }
                

                return response.bodyToMono(AuthValidationResponse.class);
            })
            .flatMap(resp -> {

                if (resp == null || !resp.isValid()) {
                    return unauthorized(exchange);
                }

                ServerHttpRequest mutatedRequest =
                        exchange.getRequest().mutate()
                                .header("X-Username", resp.getUsername())
                                .header("X-Roles", String.join(",", resp.getRoles()))
                                .build();
                  log.info("Mutated request headers: {}", mutatedRequest);

                return chain.filter(exchange.mutate().request(mutatedRequest).build());
            })
            .onErrorResume(e -> {
                log.error("Error calling auth validate API", e);
                return unauthorized(exchange);
            });
}


    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }
}
