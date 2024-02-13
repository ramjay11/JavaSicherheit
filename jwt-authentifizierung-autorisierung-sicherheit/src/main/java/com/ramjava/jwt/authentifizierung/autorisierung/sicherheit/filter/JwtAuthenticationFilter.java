package com.ramjava.jwt.authentifizierung.autorisierung.sicherheit.filter;

import com.ramjava.jwt.authentifizierung.autorisierung.sicherheit.service.JwtService;
import com.ramjava.jwt.authentifizierung.autorisierung.sicherheit.service.UserDetailsServiceImpl;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsServiceImpl userDetailsService;
    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsServiceImpl userDetails, UserDetailsServiceImpl userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);
        String nutzername = jwtService.extractNutzername(token);
        //if (nutzername == null && SecurityContextHolder.getContext().getAuthentication() == null) {
        if (nutzername != null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(nutzername);
//            UsernamePasswordAuthenticationToken(
//                    userDetails, null, userDetails.getAuthorities()
//            )
            if (jwtService.isValid(token, userDetails)) {
                var authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, "123456", userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
