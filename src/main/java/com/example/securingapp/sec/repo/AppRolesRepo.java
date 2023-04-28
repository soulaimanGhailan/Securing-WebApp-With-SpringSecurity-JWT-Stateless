package com.example.securingapp.sec.repo;


import com.example.securingapp.sec.entities.AppRoles;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRolesRepo extends JpaRepository<AppRoles, Long> {
    AppRoles findAppRolesByRoleName(String role);
}
