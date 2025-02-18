package com.sahilpaudel.keycloak.client.utils;

import java.util.Map;

public class ClassUtil {
    public static <K, V> Class<Map<K, V>> getMapClass() {
        return (Class<Map<K, V>>) (Class<?>) Map.class;
    }
}
