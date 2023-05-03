package com.example.securingapp.sec.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.securingapp.sec.entities.AppRoles;
import com.example.securingapp.sec.entities.AppUser;
import com.example.securingapp.sec.security.JWTUtils;
import com.example.securingapp.sec.security.RoleUsername;
import com.example.securingapp.sec.service.AccountService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@AllArgsConstructor
public class accountRestController {
    private AccountService accountService;

    @GetMapping("/users")
    @PostAuthorize("hasAuthority('USER')")
    public List<AppUser> getUsers(){
        return accountService.liteUsers();
    }
    @PostAuthorize("hasAuthority('ADMIN')")
    @PostMapping("/user")
    public AppUser addUser(@RequestBody AppUser appUser){
        return accountService.newAppUser(appUser);
    }
    @PostMapping("/role")
    public AppRoles addRole(@RequestBody AppRoles appRoles){
        return accountService.newAppRole(appRoles);
    }
    @PostMapping("/roleToUser")
    public void addUser(@RequestBody RoleUsername r){
         accountService.addRoleToUser(r.getRoleName() , r.getUserName());
    }
    @GetMapping(JWTUtils.REFRESH_TOKEN_ENDPOINT)
    public void refreshToken(HttpServletRequest request , HttpServletResponse response) throws Exception{
        String authToken = request.getHeader(JWTUtils.AUTH_HEADER);
        if(authToken!=null && authToken.startsWith(JWTUtils.PREFIX)){
            try{
               String username = JWTUtils.verifyJwtRefreshToken(authToken);
               AppUser appUser = accountService.LoadUserByUserName(username);
                //blacklist ....
                List<String> roles  = appUser.getAppRoles().stream().map(r -> r.getRoleName()).collect(Collectors.toList());
                String jwtAccessToken= JWTUtils.generateAccessToken(request , appUser.getUsername() , roles );
                JWTUtils.sendJwt(jwtAccessToken , authToken.substring(JWTUtils.PREFIX.length()) , response);
            }catch (Exception e){
                response.setHeader("error-message" , e.getMessage());
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
            }
        }
        else{
            throw new RuntimeException("refresh token required");
        }
    }
    @GetMapping("/profile")
    public AppUser getProfile(Principal principal){
        return accountService.LoadUserByUserName(principal.getName());
    }
}
