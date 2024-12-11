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
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 將 CSRF 保護機制禁用，因為已經使用 JWT 驗證了，不需要 CSRF 機制
                .csrf(csrf -> csrf.disable())

                // 配置授權請求
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/v1/auth/**").permitAll() // 指定公開訪問的路徑
                        .anyRequest().authenticated() // 其他所有請求都需要進行身份驗證
                )

                // 配置 Session 管理策略
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 禁用 Session，所有請求使用 JWT 驗證
                )

                // 配置自訂的 AuthenticationProvider
                .authenticationProvider(authenticationProvider)

                // 添加 JWT 驗證過濾器，在 UsernamePasswordAuthenticationFilter 之前執行
                .addFilterBefore(JwTAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
