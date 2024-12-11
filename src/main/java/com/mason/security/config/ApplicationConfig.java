package com.mason.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.mason.security.user.UserRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    @Autowired
    private final UserRepository userRepository;

    //不建立新的Class來實作介面
    @Bean
    public UserDetailsService userDetailsService(){
            //username是我們送過來的參數
            return username -> userRepository.findByEmail(username)
            //空括號代表Lambda不用參數可以執行
            .orElseThrow(()-> new UsernameNotFoundException("User Not Found"));
    };

    //利用我自訂的userDetailsService來載入資料 利用 userRepository 從資料庫中根據 email 尋找使用者資料。
    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService()); 
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    //自定義AuthenticationManager 在此使用的原因:使用資料庫的其他欄位進行驗證 在這是用E-mail
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception{
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}


