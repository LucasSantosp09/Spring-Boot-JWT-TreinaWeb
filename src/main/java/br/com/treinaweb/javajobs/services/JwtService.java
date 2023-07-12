package br.com.treinaweb.javajobs.services;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.Claims;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {

    private static final String SIGNIN_KEY = "rpvMoStbgmKuBZxlKicm858uhnjIG9oE";

    private static final int EXPIRATION_TIME = 30;

    public String generateToken(Authentication authentication) {
        Map<String, Object> claims = new HashMap<>();

        Instant currentDate = Instant.now();
        Instant expirationDate = currentDate.plusSeconds(EXPIRATION_TIME);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(authentication.getName())
                .setIssuedAt(new Date(currentDate.toEpochMilli()))
                .setExpiration(new Date(expirationDate.toEpochMilli()))
                .signWith(SignatureAlgorithm.HS512, SIGNIN_KEY)
                .compact();
    }
    public Date getExpirationFromToken(String token) {
        Claims claims = getClaims(token);

        return claims.getExpiration();
    }

    public String getUsernameFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.getSubject();
    }

    private Claims getClaims(String token) {
        return Jwts.parser()
                .setSigningKey(SIGNIN_KEY)
                .parseClaimsJws(token)
                .getBody();
    }


}
