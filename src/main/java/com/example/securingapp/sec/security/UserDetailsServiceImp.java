package com.example.securingapp.sec.security;

import com.example.securingapp.sec.entities.AppUser;
import com.example.securingapp.sec.service.AccountService;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class UserDetailsServiceImp implements UserDetailsService {
    private AccountService accountService;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser = accountService.LoadUserByUserName(username);
        Collection<GrantedAuthority> authorities = appUser.getAppRoles().stream().map(appRoles -> new SimpleGrantedAuthority(appRoles.getRoleName()))
                .collect(Collectors.toList());
        return new User(appUser.getUsername() , appUser.getPassword() , authorities);
    }
}
