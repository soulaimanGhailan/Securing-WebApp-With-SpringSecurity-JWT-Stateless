package com.example.securingapp.sec.service;

import com.example.securingapp.sec.entities.AppRoles;
import com.example.securingapp.sec.entities.AppUser;
import com.example.securingapp.sec.repo.AppRolesRepo;
import com.example.securingapp.sec.repo.AppUserRepo;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
@AllArgsConstructor
public class AccountServiceImpl implements AccountService {
    private AppRolesRepo appRolesRepo;
    private AppUserRepo appUserRepo;
    private PasswordEncoder passwordEncoder;
    @Override
    public AppRoles newAppRole(AppRoles appRoles) {
        return appRolesRepo.save(appRoles);
    }

    @Override
    public AppUser newAppUser(AppUser appUser) {
        String pass = appUser.getPassword();
        appUser.setPassword(passwordEncoder.encode(pass));
        return appUserRepo.save(appUser);
    }

    @Override
    public void addRoleToUser(String role, String uName) {
        AppUser appUser = appUserRepo.findAppUserByUsername(uName);
        AppRoles appRole = appRolesRepo.findAppRolesByRoleName(role);
        appUser.getAppRoles().add(appRole);
    }

    @Override
    public AppUser LoadUserByUserName(String Uname) {
        return appUserRepo.findAppUserByUsername(Uname);
    }

    @Override
    public List<AppUser> liteUsers() {
        return appUserRepo.findAll();
    }
}
