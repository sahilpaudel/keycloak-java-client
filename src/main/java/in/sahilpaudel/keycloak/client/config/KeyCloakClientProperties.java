package in.sahilpaudel.keycloak.client.config;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@ToString
@ConfigurationProperties(prefix = "com.sahilpaudel.keycloak.client")
public class KeyCloakClientProperties {
    private String realm;
    private String clientId;
    private String clientSecret;
    private String authServerUrl;
    private int readTimeout = 2000;
    private int connectTimeout = 1000;
    private Duration cacheDurationInHours = Duration.ofHours(6);
    private List<String> exchangeFilterFunctionBeans = new ArrayList<>();
    private String baseUrl = "https://staging.keycloak.com";
}
