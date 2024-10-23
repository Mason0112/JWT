package com.mason.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {


    private final  JWTAuthenticationFilter JwTAuthenticationFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http
            //將csrf保護機制禁用 因為已經使用JWT驗證了 不需要csrf機制
            .csrf()
            .disable()
            .authorizeHttpRequests()//開始設置授權請求
            .requestMatchers("")//指定公開訪問的路徑
            .permitAll()//任何人都可以訪問
            .anyRequest()//其他所有請求
            .authenticated()//都要進行身分驗證
            .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authenticationProvider(authenticationProvider)
            .addFilterBefore(JwTAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);



            

        
        return http.build();
    }

}
