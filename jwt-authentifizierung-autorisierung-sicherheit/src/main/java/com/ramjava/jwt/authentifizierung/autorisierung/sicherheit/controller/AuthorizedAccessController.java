package com.ramjava.jwt.authentifizierung.autorisierung.sicherheit.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthorizedAccessController {
    @GetMapping("/authorized")
    public ResponseEntity<String> securedUrl() {
        return ResponseEntity.ok("Hallo von einer gesicherten URL");
    }

    @GetMapping("/admin_only")
    public ResponseEntity<String> adminOnly() {
        return ResponseEntity.ok("Zugriff nur für Administratoren");
    }
}
