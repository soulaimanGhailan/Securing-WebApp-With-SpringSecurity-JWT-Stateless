package com.example.securingapp.sec.security.serurityConfig;


import com.example.securingapp.sec.security.JWTUtils;
import com.example.securingapp.sec.security.filters.JwtAuthenticationFilter;
import com.example.securingapp.sec.security.filters.JwtAuthorizationFiler;
import com.example.securingapp.sec.security.UserDetailsServiceImp;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class appSecurityConfig extends WebSecurityConfigurerAdapter {
    private UserDetailsServiceImp userDetailsServiceImp;

    public appSecurityConfig(UserDetailsServiceImp userDetailsServiceImp) {
        this.userDetailsServiceImp = userDetailsServiceImp;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsServiceImp);

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.headers().frameOptions().disable();
        http.csrf().disable();
//        http.formLogin();
        http.authorizeRequests().antMatchers(JWTUtils.REFRESH_TOKEN_ENDPOINT+"/**").permitAll();
        //we can use annotation instead
//        http.authorizeRequests().antMatchers(HttpMethod.POST  , "/user/**").hasAuthority("ADMIN");
        http.authorizeRequests().anyRequest().authenticated();
        //admin who can add user
        http.addFilter(new JwtAuthenticationFilter(authenticationManagerBean()));
        http.addFilterBefore(new JwtAuthorizationFiler() , UsernamePasswordAuthenticationFilter.class);
    }


    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
