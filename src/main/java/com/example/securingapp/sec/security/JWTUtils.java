package com.example.securingapp.sec.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

public class JWTUtils {
    public static final String SECRET = "secret!@#$/mySecret";
    public static final String AUTH_HEADER = "Authorization";
    public static final long EXPIRED_ZONE_ACCESS_TOKEN = 60*60*1000; // one hour
    public static final long EXPIRED_ZONE_REFRESH_TOKEN = 3*30*24*60*60*1000; // three months
    public static final Algorithm algorithm=Algorithm.HMAC256(SECRET);
    public static final String  PREFIX ="Bearer ";
    public static final String  REFRESH_TOKEN_ENDPOINT ="/refreshToken";
    public static String generateAccessToken(HttpServletRequest request , String username , List<String> roles){
         return  JWT.create()
                .withSubject(username)
                .withExpiresAt(new Date(System.currentTimeMillis()+EXPIRED_ZONE_ACCESS_TOKEN))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("role" , roles)
                .sign(algorithm);
    }
    public static String generateRefreshToken(HttpServletRequest request , String username ){
        return  JWT.create()
                .withSubject(username)
                .withExpiresAt(new Date(System.currentTimeMillis()+EXPIRED_ZONE_REFRESH_TOKEN))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);
    }
    public static void sendJwt(String jwtAccessToken , String jwtRefreshToken , HttpServletResponse response) throws IOException {
        Map<String , String> idTokens = new HashMap<>();
        idTokens.put("access-Token" , jwtAccessToken) ;
        idTokens.put("refresh-Token" , jwtRefreshToken) ;
        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream() , idTokens);
    }
    public static UsernamePasswordAuthenticationToken verifyJwtAccessToken(String authorizationToken) throws Exception{
        String jwt = authorizationToken.substring(PREFIX.length());
        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
        String username = decodedJWT.getSubject();
        String[] roles = decodedJWT.getClaim("role").asArray(String.class);
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        for (String r :roles) {
            authorities.add(new SimpleGrantedAuthority(r));
        }
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username , null , authorities);
        return authenticationToken;
    }
    public static String verifyJwtRefreshToken(String authorizationToken) throws Exception{
        String jwt = authorizationToken.substring(PREFIX.length());
        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
        String username = decodedJWT.getSubject();
        return username;
    }


}
