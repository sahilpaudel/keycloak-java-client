package com.sahilpaudel.keycloak.client;

import in.sahilpaudel.keycloak.client.annotations.RoleGuard;
import in.sahilpaudel.keycloak.client.annotations.RoleMatching;
import in.sahilpaudel.keycloak.client.aspects.AuthGuardAspect;
import in.sahilpaudel.keycloak.client.config.KeyCloakClientProperties;
import com.sahilpaudel.keycloak.client.controller.TestController;
import in.sahilpaudel.keycloak.client.service.KeycloakClientService;
import io.jsonwebtoken.*;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.reflect.CodeSignature;
import org.aspectj.lang.reflect.MethodSignature;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest(classes = {KeyCloakClientProperties.class, KeycloakClientService.class, HttpServletRequest.class})
public class MyTest {

    @MockBean
    private RestTemplate restTemplate;

    @MockBean
    private HttpServletRequest request;

    @MockBean
    private KeycloakClientService keycloakClientService;

    private KeyCloakClientProperties keyCloakClientProperties;

    private AuthGuardAspect authGuardAspect;

    @BeforeEach
    void init() {

        keyCloakClientProperties = new KeyCloakClientProperties();
        keyCloakClientProperties.setRealm("Hastinapur");

        Map<String, String> data = Map.of("realm", "Hastinapur", "public_key", "public-key");
        when(restTemplate.getForObject(Mockito.anyString(), Mockito.any()))
                .thenAnswer(invocation -> ResponseEntity.ok(data));
        when(keycloakClientService.getRealmInfo(Mockito.anyString()))
                .thenReturn(data);

        authGuardAspect = new AuthGuardAspect(request, keycloakClientService, keyCloakClientProperties);
    }

    @Test
    void testNonAuthorizedRequest() throws Exception {

        JoinPoint joinPoint = mock(JoinPoint.class);
        MethodSignature methodSignature = mock(MethodSignature.class);

        Method method = TestController.class.getMethod("privateTest");

        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getMethod()).thenReturn(method);
        when(methodSignature.getDeclaringType()).thenReturn(method.getDeclaringClass());

        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);

        assertThrows(ResponseStatusException.class, () -> {
            authGuardAspect.doCheckForAuthentication(joinPoint);
        });
    }

    @Test
    public void testDoCheckForAuthentication_InvalidToken() throws Exception {
        String invalidToken = "invalidToken";
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + invalidToken);

        JoinPoint joinPoint = mock(JoinPoint.class);
        MethodSignature methodSignature = mock(MethodSignature.class);
        Method method = TestController.class.getMethod("privateTest");

        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getMethod()).thenReturn(method);
        when(methodSignature.getDeclaringType()).thenReturn(method.getDeclaringClass());
        try {
            authGuardAspect.doCheckForAuthentication(joinPoint);
            fail("Expected ResponseStatusException");
        } catch (ResponseStatusException e) {
            assertEquals(HttpStatus.UNAUTHORIZED, e.getStatus());
            assertEquals("Unable to verify token", e.getReason());
        }
    }

    @Test
    public void testDoCheckForAuthentication_ValidToken() throws Exception {
        String validToken = "this.valid.token";
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + validToken);

        AuthGuardAspect mAuthGuardAspect = mock(AuthGuardAspect.class);

        JoinPoint joinPoint = mock(JoinPoint.class);
        MethodSignature methodSignature = mock(MethodSignature.class);
        Method method = TestController.class.getMethod("privateTest");

        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getMethod()).thenReturn(method);
        when(methodSignature.getDeclaringType()).thenReturn(method.getDeclaringClass());

        Claims claims = mock(Claims.class);

        when(mAuthGuardAspect.verifyToken(validToken)).thenReturn(claims);

        mAuthGuardAspect.doCheckForAuthentication(joinPoint);
        mAuthGuardAspect.verifyToken(validToken);
    }

    @Test
    public void testDoCheckForAuthentication_Public() throws Exception {
        JoinPoint joinPoint = mock(JoinPoint.class);
        MethodSignature methodSignature = mock(MethodSignature.class);
        Method method = TestController.class.getMethod("publicTest");

        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getMethod()).thenReturn(method);
        when(methodSignature.getDeclaringType()).thenReturn(method.getDeclaringClass());
        authGuardAspect.doCheckForAuthentication(joinPoint);
    }

    @Test
    public void testDoCheckForAuthentication_Private() throws Exception {
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("");
        JoinPoint joinPoint = mock(JoinPoint.class);
        CodeSignature methodSignature = mock(CodeSignature.class);
        Method method = TestController.class.getMethod("privateTest");

        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getDeclaringType()).thenReturn(method.getDeclaringClass());
        try {
            authGuardAspect.doCheckForAuthentication(joinPoint);
            fail("Expected ResponseStatusException");
        } catch (ResponseStatusException e) {
            assertEquals(HttpStatus.UNAUTHORIZED, e.getStatus());
            assertEquals("Authorization token is Missing or Invalid.", e.getReason());
        }

        try {
            when(methodSignature.getDeclaringType()).thenReturn(null);
            authGuardAspect.doCheckForAuthentication(joinPoint);
        } catch (ResponseStatusException e) {
            assertEquals(HttpStatus.UNAUTHORIZED, e.getStatus());
            assertEquals("Authorization token is Missing or Invalid.", e.getReason());
        }
    }

    @Test
    public void testDoCheckForAuthentication_doInjectUserData() throws Exception {
        JoinPoint joinPoint = mock(JoinPoint.class);
        MethodSignature methodSignature = mock(MethodSignature.class);
        Method method = TestController.class.getMethod("getUser", HashMap.class);

        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getMethod()).thenReturn(method);

        Map<String, Object> userDetails = Map.of("email", "user@gmail.com");
        Claims mockClaims = mock(Claims.class);
        when(mockClaims.keySet()).thenReturn(userDetails.keySet());
        when(mockClaims.get("email")).thenReturn("user@gmail.com");

        Map<String, Object> targetMap = new HashMap<>();
        Object[] args = new Object[]{targetMap};
        when(joinPoint.getArgs()).thenReturn(args);

        authGuardAspect.doInjectUserData(joinPoint, mockClaims);
        assertEquals(userDetails.get("email"), targetMap.get("email"));
    }

    @Test
    public void testDoCheckForAuthentication_RoleGuard() throws Exception {
        JoinPoint joinPoint = mock(JoinPoint.class);
        Method method = TestController.class.getMethod("roleTest");

        MethodSignature methodSignature = mock(MethodSignature.class);
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getMethod()).thenReturn(method);

        assertEquals(authGuardAspect.isRoleGuardMethod(joinPoint), method.isAnnotationPresent(RoleGuard.class));

        RoleGuard roleGuard = authGuardAspect.doGetRoleGuardAnnotation(joinPoint);

        assertEquals(roleGuard.mode(), RoleMatching.ANY);

        assertEquals(roleGuard.roles()[0], "PDF_UPLOADER");
    }
}
