package com.pharmeasy.keycloak.client;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "com.pharmeasy")
public class KeyCloakTestServer {
    public static void main(String[] args) {
        SpringApplication.run(KeyCloakTestServer.class, args);
    }
}
