package com.sahilpaudel.keycloak.client;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "com.sahilpaudel")
public class KeyCloakTestServer {
    public static void main(String[] args) {
        SpringApplication.run(KeyCloakTestServer.class, args);
    }
}
