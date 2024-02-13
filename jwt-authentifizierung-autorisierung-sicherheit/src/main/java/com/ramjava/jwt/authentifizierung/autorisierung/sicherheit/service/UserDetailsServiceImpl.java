package com.ramjava.jwt.authentifizierung.autorisierung.sicherheit.service;

import com.ramjava.jwt.authentifizierung.autorisierung.sicherheit.model.Benutzer;
import com.ramjava.jwt.authentifizierung.autorisierung.sicherheit.repository.BenutzerRepo;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private final BenutzerRepo benutzerRepo;

    public UserDetailsServiceImpl(BenutzerRepo benutzerRepo) {
        this.benutzerRepo = benutzerRepo;
    }

    @Override
    public UserDetails loadUserByUsername(String nutzername) throws UsernameNotFoundException {
        Benutzer benutzer = benutzerRepo.findByNutzername(nutzername)
                .orElseThrow(() -> new UsernameNotFoundException("Benutzername nicht gefunden"));

        // Populate UserDetails object with Benutzer details including password
        return org.springframework.security.core.userdetails.User
                .withUsername(benutzer.getNutzername())
                .password(benutzer.getPasswort()) // Populate password field
                .authorities(benutzer.getAuthorities()) // Assuming getAuthorities returns a Collection<? extends GrantedAuthority>
                .accountExpired(!benutzer.isAccountNonExpired())
                .accountLocked(!benutzer.isAccountNonLocked())
                .credentialsExpired(!benutzer.isCredentialsNonExpired())
                .disabled(!benutzer.isEnabled())
                .build();
    }
}