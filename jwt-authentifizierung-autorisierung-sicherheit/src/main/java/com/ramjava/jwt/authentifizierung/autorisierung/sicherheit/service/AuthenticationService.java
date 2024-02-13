package com.ramjava.jwt.authentifizierung.autorisierung.sicherheit.service;

import com.ramjava.jwt.authentifizierung.autorisierung.sicherheit.model.AuthenticationResponse;
import com.ramjava.jwt.authentifizierung.autorisierung.sicherheit.model.Benutzer;
import com.ramjava.jwt.authentifizierung.autorisierung.sicherheit.repository.BenutzerRepo;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthenticationService {
    private final BenutzerRepo benutzerRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationService(BenutzerRepo benutzerRepo, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager) {
        this.benutzerRepo = benutzerRepo;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    public AuthenticationResponse register(Benutzer request) {
        var benutzer = new Benutzer();
        benutzer.setVorname(request.getVorname());
        benutzer.setFamilienname(request.getFamilienname());
        benutzer.setNutzername(request.getNutzername());
        benutzer.setPasswort(passwordEncoder.encode(request.getPasswort()));
        benutzer.setRolle(request.getRolle());
        benutzer = benutzerRepo.save(benutzer);
        String token = jwtService.generateToken(benutzer);
        return new AuthenticationResponse(token);
    }

    public AuthenticationResponse authenticate(Benutzer request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getNutzername(),
                        request.getPasswort()
                )
        );
        Benutzer benutzer = benutzerRepo.findByNutzername(request.getNutzername()).orElseThrow();
        String token = jwtService.generateToken(benutzer);
        return new AuthenticationResponse(token);
    }
}
