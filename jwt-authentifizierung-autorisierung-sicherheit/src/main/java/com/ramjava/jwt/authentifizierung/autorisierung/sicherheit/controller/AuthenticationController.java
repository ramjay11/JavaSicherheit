package com.ramjava.jwt.authentifizierung.autorisierung.sicherheit.controller;

import com.ramjava.jwt.authentifizierung.autorisierung.sicherheit.model.AuthenticationResponse;
import com.ramjava.jwt.authentifizierung.autorisierung.sicherheit.model.Benutzer;
import com.ramjava.jwt.authentifizierung.autorisierung.sicherheit.service.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody Benutzer request) {
        return ResponseEntity.ok(authenticationService.register(request));
    }
    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody Benutzer request) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }
}
