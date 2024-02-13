package com.ramjava.jwt.authentifizierung.autorisierung.sicherheit.repository;

import com.ramjava.jwt.authentifizierung.autorisierung.sicherheit.model.Benutzer;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface BenutzerRepo extends JpaRepository<Benutzer, Integer> {
    // Benutzerdefinierte Methode
    Optional<Benutzer> findByNutzername(String nutzername);
}
