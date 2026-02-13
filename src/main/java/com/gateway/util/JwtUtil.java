package com.gateway.util;

import java.util.Date;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {

	private final String SECRET = "mySecretKeyForJwtTokenGeneration83499746681";
	
	//1.its convert secret key into byte format 
	public Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(SECRET.getBytes()))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

	//2. its check token is valid or not
    public boolean isTokenValid(String token) {
        try {
            extractClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    //3. check if token expired
    public boolean isTokenExpired(String token) {
        return extractClaims(token)
                .getExpiration()
                .before(new Date());
    }

    //4. fetch user from the token
    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    //5. fetch role from the token
    public String extractRole(String token) {
        return extractClaims(token).get("role", String.class);
    }
	
}
