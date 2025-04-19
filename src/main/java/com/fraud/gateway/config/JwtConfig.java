package com.fraud.gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class JwtConfig {

    @Value("${clerk.jwks-url}")
    private String jwksUrl;

    @Bean
    public WebClient.Builder webClientBuilder() {
        return WebClient.builder();
    }

    public String getJwksUrl() {
        return jwksUrl;
    }
} 