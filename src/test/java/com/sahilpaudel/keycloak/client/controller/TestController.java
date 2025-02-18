package com.sahilpaudel.keycloak.client.controller;

import com.sahilpaudel.keycloak.client.annotations.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

@AuthGuard
@RestController
@RequestMapping("/api/v1")
public class TestController {

    @GetMapping("/test")
    public ResponseEntity<Object> privateTest() {
        return ResponseEntity.ok().body("success");
    }

    @GetMapping("/user")
    public ResponseEntity<Object> getUser(@User() HashMap<String, Object> user) {
        return ResponseEntity.ok().body(user);
    }

    @Public
    @GetMapping("/public")
    public ResponseEntity<Object> publicTest() {
        return ResponseEntity.ok().body("success");
    }

    @RoleGuard(roles = {"PDF_UPLOADER"}, mode = RoleMatching.ANY)
    @GetMapping("/role")
    public ResponseEntity<Object> roleTest() {
        return ResponseEntity.ok().body("success");
    }
}
