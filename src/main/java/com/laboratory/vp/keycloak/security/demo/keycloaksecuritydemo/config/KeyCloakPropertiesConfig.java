package com.laboratory.vp.keycloak.security.demo.keycloaksecuritydemo.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(value = KeyCloakPropertiesConfig.class)
@ConfigurationProperties(value = "keycloak")
@Data
public class KeyCloakPropertiesConfig {
    private String authServerUrl;
}
