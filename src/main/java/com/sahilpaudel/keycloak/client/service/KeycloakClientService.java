package com.sahilpaudel.keycloak.client.service;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.sahilpaudel.keycloak.client.utils.ClassUtil;
import com.sahilpaudel.keycloak.client.config.KeyCloakClientProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import javax.annotation.PostConstruct;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class KeycloakClientService {

    private final RestTemplate keyCloakRestTemplate;
    private final KeyCloakClientProperties keyCloakClientProperties;
    private LoadingCache<String, Map<String, String>> realmInfoCache;

    @PostConstruct
    public void init() {
        log.debug("Initializing AuthGuardAspect...");
        doFetchRealmInfo();
        log.debug("Initialized AuthGuardAspect {}", keyCloakClientProperties);
        log.debug("Realm Information {}", realmInfoCache.get(keyCloakClientProperties.getRealm()));
    }

    private void doFetchRealmInfo() {
        realmInfoCache = Caffeine
                .newBuilder()
                .maximumSize(1000L)
                .build(realmKey -> {
                    try {
                        log.debug("Fetching realm info from keycloak server {}", keyCloakClientProperties.getRealm());
                        String baseUrl = keyCloakClientProperties.getBaseUrl();
                        String url = String.format("%s/realms/%s", baseUrl, realmKey);
                        return keyCloakRestTemplate.getForObject(url, ClassUtil.getMapClass());
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    public Map<String, String> getRealmInfo(String realm) {
        return realmInfoCache.get(realm);
    }
}
