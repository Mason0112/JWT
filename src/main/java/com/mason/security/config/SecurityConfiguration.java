package com.mason.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import lombok.NoArgsConstructor;

@Configuration
@EnableWebFluxSecurity
@NoArgsConstructor
public class SecurityConfiguration {


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http){
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests()
            .requestMatchers(null)
            .permitAll()
            .anyRequest()
            .authenticated()
            .and()
            .sessionMangement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authenticationProvider(authenticationProvider)
            .addFilterBefore(JWTAuthfi)

        
        return http.build();
    }

}
