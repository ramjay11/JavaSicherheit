package com.ramjava.jwt.authentifizierung.autorisierung.sicherheit.service;

import com.ramjava.jwt.authentifizierung.autorisierung.sicherheit.model.Benutzer;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

// Token Generation and Validation
@Service
public class JwtService {
    //
    private final String SECRET_KEY = "ff77f24fb28e0cb3e026ace6ddf82ab0a27fcc70eedd0d592f21c48aec08286a";
    public String extractNutzername(String token) {
        return extractClaims(token, Claims::getSubject);
    }
    public Boolean isValid(String token, UserDetails benutzer) {
        String nutzername = extractNutzername(token);
        return (nutzername.equals(benutzer.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
    private Date extractExpiration(String token) {
        return extractClaims(token, Claims::getExpiration);
    }

    public <T> T extractClaims(String token, Function<Claims, T> resolver) {
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }
    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
    // Token Generation
    public String generateToken(Benutzer benutzer) {
        String token = Jwts
                .builder()
                .subject(benutzer.getNutzername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 24 * 60 * 60 * 100))
                .signWith(getSigningKey())
                .compact();
        return token;
    }
    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64URL.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
