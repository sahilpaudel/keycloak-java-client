package com.pharmeasy.keycloak.client.aspects;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pharmeasy.keycloak.client.annotations.*;
import com.pharmeasy.keycloak.client.config.KeyCloakClientProperties;
import com.pharmeasy.keycloak.client.dto.Role;
import com.pharmeasy.keycloak.client.service.KeycloakClientService;
import com.pharmeasy.keycloak.client.utils.ClassUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Slf4j
@Aspect
@Component
@RequiredArgsConstructor
public class AuthGuardAspect {

    private final HttpServletRequest request;
    private final KeycloakClientService keycloakClientService;
    private final KeyCloakClientProperties keyCloakClientProperties;

    private final static ObjectMapper objectMapper = new ObjectMapper();

    public PublicKey doGetPublicKey() throws Exception {
        Map<String, String> realmInfo = keycloakClientService.getRealmInfo(keyCloakClientProperties.getRealm());
        String publicKey = realmInfo.get("public_key");
        if (publicKey == null || publicKey.isEmpty()) {
            throw new RuntimeException("unable to fetch realm info to extract public key");
        }

        byte[] decoded = Base64.getDecoder().decode(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(decoded));
    }

    public Claims verifyToken(String token) {
        try {
            JwtParser jwtParser = Jwts.parserBuilder().setSigningKey(doGetPublicKey()).build();
            Claims claims = jwtParser.parseClaimsJws(token).getBody();
            log.debug("Claims from token {}", claims);
            return claims;
        } catch (Exception e) {
            log.debug("Token might have expired {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unable to verify token", e);
        }
    }

    @Pointcut("@within(org.springframework.web.bind.annotation.RequestMapping) || @annotation(org.springframework.web.bind.annotation.RequestMapping)")
    public void doRequestMappingMethods() {
    }

    @Before("doRequestMappingMethods()")
    public void doCheckForAuthentication(JoinPoint joinPoint) {
        if (isPublicMethod(joinPoint)) {
            return;
        }

        if (isAuthGuardClass(joinPoint)) {
            String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authorization token is Missing or Invalid.");
            }

            String token = authHeader.substring(7);
            Claims claims = verifyToken(token);

            doInjectUserData(joinPoint, claims);

            if (isRoleGuardMethod(joinPoint)) {
                Set<String> clientRoles = doGetClientRoles(claims);
                log.debug("Client roles {}", clientRoles);

                RoleGuard roleGuard = doGetRoleGuardAnnotation(joinPoint);
                if (!hasRole(roleGuard, clientRoles)) {
                    log.debug("Insufficient roles.");
                    throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Insufficient roles.");
                }
            }
        }
    }

    private boolean hasRole(RoleGuard roleGuard, Set<String> userRoles) {
        Set<String> annotationRoles = Set.of(roleGuard.roles());
        if (roleGuard.mode() == RoleMatching.ALL) {
            return userRoles.containsAll(annotationRoles);
        }
        return userRoles.stream().anyMatch(annotationRoles::contains);
    }

    private Set<String> doGetClientRoles(Claims claims) {
        String clientId = keyCloakClientProperties.getClientId();
        Map<String, Map<String, Role>> resourceAccess = claims.get("resource_access", ClassUtil.getMapClass());
        if (resourceAccess == null || resourceAccess.isEmpty())
            return Set.of();
        Role roles = objectMapper.convertValue(resourceAccess.get(clientId), Role.class);
        if (roles == null || roles.getRoles() == null || roles.getRoles().isEmpty())
            return Set.of();
        return roles.getRoles();
    }

    public void doInjectUserData(JoinPoint joinPoint, Claims claims) {
        Method method = ((MethodSignature) joinPoint.getSignature()).getMethod();
        Object[] args = joinPoint.getArgs();

        Map<String, Object> user = doGetUserDetailsFromClaims(claims);
        for (int i = 0; i < method.getParameters().length; i++) {
            if (method.getParameters()[i].isAnnotationPresent(User.class)) {
                if(args[i] instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> targetMap = (Map<String, Object>) args[i];
                    targetMap.putAll(user);
                }
            }
        }
    }

    private Map<String, Object> doGetUserDetailsFromClaims(Claims claims) {
        Map<String, Object> userDetails = new HashMap<>();
        if (claims != null) {
            for (String key : claims.keySet()) {
                userDetails.put(key, claims.get(key));
            }
        }
        return userDetails;
    }

    private boolean isPublicMethod(JoinPoint joinPoint) {
        if (joinPoint.getSignature() instanceof MethodSignature) {
            MethodSignature signature = (MethodSignature) joinPoint.getSignature();
            return signature.getMethod().isAnnotationPresent(Public.class);
        }
        return false;
    }

    private boolean isAuthGuardClass(JoinPoint joinPoint) {
        Class<?> clazz = joinPoint.getSignature().getDeclaringType();
        return clazz != null && clazz.isAnnotationPresent(AuthGuard.class);
    }

    public boolean isRoleGuardMethod(JoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        return signature.getMethod().isAnnotationPresent(RoleGuard.class);
    }

    public RoleGuard doGetRoleGuardAnnotation(JoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        return signature.getMethod().getAnnotation(RoleGuard.class);
    }
}