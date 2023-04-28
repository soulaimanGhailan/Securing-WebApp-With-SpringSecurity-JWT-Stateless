package com.example.securingapp.sec.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.securingapp.sec.entities.AppRoles;
import com.example.securingapp.sec.entities.AppUser;
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
    public void addUser(@RequestBody roleUserForm r){
         accountService.addRoleToUser(r.getRoleName() , r.getUserName());
    }
    @GetMapping("/refreshToken")
    public void refreshToken(HttpServletRequest request , HttpServletResponse response) throws Exception{
        String authToken = request.getHeader("Authorization");
        if(authToken!=null && authToken.startsWith("Bearer")){
            try{
                String jwt = authToken.substring(7);
                Algorithm algorithm = Algorithm.HMAC256("secret!@#$");
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                String username = decodedJWT.getSubject();
                AppUser appUser = accountService.LoadUserByUserName(username);
                //blacklist
                String jwtAccessToken= JWT.create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+2*60*1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("role" , appUser.getAppRoles().stream().map(appRoles -> appRoles.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String , String> idTokens = new HashMap<>();
                idTokens.put("accessToken" , jwtAccessToken) ;
                idTokens.put("refreshToken" , jwt) ;
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream() , idTokens);

            }catch (Exception e){
                response.setHeader("error-message" , e.getMessage());
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
            }
        }
    }
}
@Data
 class roleUserForm {
    private String userName ;
    private String roleName ;
}
