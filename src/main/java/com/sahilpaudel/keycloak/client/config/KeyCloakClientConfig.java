package com.sahilpaudel.keycloak.client.config;

import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.HttpClients;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;


@Configuration
@EnableConfigurationProperties(KeyCloakClientProperties.class)
public class KeyCloakClientConfig {
    private RestTemplate getRestTemplate(KeyCloakClientProperties keyCloakClientProperties, ApplicationContext context) {
        HttpClient httpClient = HttpClients.custom()
                .setDefaultRequestConfig(RequestConfig.custom()
                        .setConnectTimeout(keyCloakClientProperties.getConnectTimeout())
                        .setSocketTimeout(keyCloakClientProperties.getReadTimeout())
                        .build())
                .build();

        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(httpClient);

        RestTemplate restTemplate = new RestTemplate(factory);

        if (keyCloakClientProperties.getExchangeFilterFunctionBeans() != null) {
            for (String bean : keyCloakClientProperties.getExchangeFilterFunctionBeans()) {
                ClientHttpRequestInterceptor interceptor = (ClientHttpRequestInterceptor) context.getBean(bean);
                restTemplate.getInterceptors().add(interceptor);
            }
        }

        return restTemplate;
    }

    @Bean("keyCloakRestTemplate")
    public RestTemplate keyCloakRestTemplate(KeyCloakClientProperties keyCloakClientProperties, ApplicationContext context) {
        return getRestTemplate(keyCloakClientProperties, context);
    }
}
