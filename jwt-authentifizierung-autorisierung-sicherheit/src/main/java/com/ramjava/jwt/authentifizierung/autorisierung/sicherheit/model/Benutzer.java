package com.ramjava.jwt.authentifizierung.autorisierung.sicherheit.model;

//import jakarta.persistence.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import java.util.Collection;
import java.util.List;

@Entity @Table(name = "user")
public class Benutzer implements UserDetails {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    @Column(name = "firstname")
    private String vorname;
    @Column(name = "lastname")
    private String familienname;
    @Column(name = "username")
    private String nutzername;
    @Column(name = "password")
    private String passwort;
    @Enumerated(value = EnumType.STRING)
    Rolle rolle;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getVorname() {
        return vorname;
    }

    public void setVorname(String vorname) {
        this.vorname = vorname;
    }

    public String getFamilienname() {
        return familienname;
    }

    public void setFamilienname(String familienname) {
        this.familienname = familienname;
    }

    public String getNutzername() {
        return nutzername;
    }

    public void setNutzername(String nutzername) {
        this.nutzername = nutzername;
    }

    public String getPasswort() {
        return passwort;
    }

    public void setPasswort(String passwort) {
        this.passwort = passwort;
    }

    public Rolle getRolle() {
        return rolle;
    }

    public void setRolle(Rolle rolle) {
        this.rolle = rolle;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(rolle.name()));
    }

    @Override
    public String getPassword() {
        return passwort;
    }

    @Override
    public String getUsername() {
        return nutzername;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
