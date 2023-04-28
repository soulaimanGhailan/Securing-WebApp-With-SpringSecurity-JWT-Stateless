package com.example.securingapp.sec.repo;


import com.example.securingapp.sec.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepo extends JpaRepository<AppUser, Long> {
    AppUser findAppUserByUsername(String uname);
}
