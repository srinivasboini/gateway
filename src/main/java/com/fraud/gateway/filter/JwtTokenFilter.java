package com.fraud.gateway.filter;

import com.fraud.gateway.config.JwtConfig;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.List;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtTokenFilter extends AbstractGatewayFilterFactory<JwtTokenFilter.Config> {

    private final WebClient webClient;
    private final JwtConfig jwtConfig;

    public JwtTokenFilter(WebClient.Builder webClientBuilder, JwtConfig jwtConfig) {
        super(Config.class);
        this.webClient = webClientBuilder.build();
        this.jwtConfig = jwtConfig;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return Mono.error(new RuntimeException("Missing or invalid Authorization header"));
            }

            String token = authHeader.substring(7);
            
            return validateToken(token)
                    .flatMap(isValid -> {
                        if (isValid) {
                            ServerHttpRequest modifiedRequest = request.mutate()
                                    .header("X-Auth-Token", token)
                                    .build();
                            return chain.filter(exchange.mutate().request(modifiedRequest).build());
                        }
                        return Mono.error(new RuntimeException("Invalid token"));
                    });
        };
    }

    private Mono<Boolean> validateToken(String token) {
        return fetchJwkSet()
                .flatMap(jwkSet -> {
                    try {
                        SignedJWT signedJWT = SignedJWT.parse(token);
                        List<RSAKey> rsaKeys = jwkSet.getKeys().stream()
                                .filter(key -> key instanceof RSAKey)
                                .map(key -> (RSAKey) key)
                                .collect(Collectors.toList());
                        
                        if (rsaKeys.isEmpty()) {
                            return Mono.error(new RuntimeException("No RSA keys found in JWKS"));
                        }

                        RSAKey rsaKey = rsaKeys.get(0);
                        JWSVerifier verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());
                        
                        return Mono.just(signedJWT.verify(verifier));
                    } catch (ParseException e) {
                        log.error("Failed to parse JWT: {}", e.getMessage());
                        return Mono.error(new RuntimeException("Invalid token format"));
                    } catch (Exception e) {
                        log.error("Token validation failed: {}", e.getMessage());
                        return Mono.error(new RuntimeException("Token validation failed"));
                    }
                });
    }

    private Mono<JWKSet> fetchJwkSet() {
        return webClient.get()
                .uri(jwtConfig.getJwksUrl())
                .retrieve()
                .bodyToMono(String.class)
                .map(jwksJson -> {
                    try {
                        return JWKSet.parse(jwksJson);
                    } catch (ParseException e) {
                        throw new RuntimeException("Failed to parse JWKS", e);
                    }
                });
    }

    public static class Config {
        // Add configuration properties if needed
    }
} 