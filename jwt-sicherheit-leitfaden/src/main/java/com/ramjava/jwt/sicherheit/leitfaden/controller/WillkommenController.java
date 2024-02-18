package com.ramjava.jwt.sicherheit.leitfaden.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WillkommenController {
    @GetMapping
    public String willkommen() {
        return "Hallo, Willkommen!";
    }
}
