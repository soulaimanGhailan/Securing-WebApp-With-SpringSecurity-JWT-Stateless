package com.example.securingapp.sec.service;


import com.example.securingapp.sec.entities.AppRoles;
import com.example.securingapp.sec.entities.AppUser;

import java.util.List;

public interface AccountService {
    AppRoles newAppRole(AppRoles appRoles);
    AppUser newAppUser(AppUser appUser);
    void addRoleToUser(String role , String uName);
    AppUser LoadUserByUserName(String Uname);
    List<AppUser> liteUsers();
}
