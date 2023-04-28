package com.example.securingapp;


import com.example.securingapp.sec.entities.AppRoles;
import com.example.securingapp.sec.entities.AppUser;
import com.example.securingapp.sec.service.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
// configure access to users
@EnableGlobalMethodSecurity(prePostEnabled = true  , securedEnabled = true)
public class SecuringAppApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecuringAppApplication.class, args);
	}
	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}
	@Bean
	CommandLineRunner start(AccountService accountService){
		return args -> {
			accountService.newAppRole(new AppRoles(null , "USER"));
			accountService.newAppRole(new AppRoles(null , "ADMIN"));
			accountService.newAppRole(new AppRoles(null , "VISITOR"));

			accountService.newAppUser(new AppUser(null , "user1" , "1234" ,  new ArrayList<>()));
			accountService.newAppUser(new AppUser(null , "user2" , "1234" ,  new ArrayList<>()));
			accountService.newAppUser(new AppUser(null , "user3" , "1234" ,  new ArrayList<>()));
			accountService.newAppUser(new AppUser(null , "user4" , "1234" ,  new ArrayList<>()));

			accountService.addRoleToUser("USER" , "user1");
			accountService.addRoleToUser("USER" , "user2");
			accountService.addRoleToUser("ADMIN" , "user2");
			accountService.addRoleToUser("VISITOR" , "user3");
			accountService.addRoleToUser("USER" , "user4");
		};
	}
}
