package com.mason.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.mason.security.user.UserRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private UserRepository userRepository;

    //不建立新的Class來實作介面
    @Bean
    public UserDetailsService userDetailsService(){
            //username是我們送過來的參數
            return username -> userRepository.findByEmail(username)
            //空括號代表Lambda不用參數可以執行
            .orElseThrow(()-> new UsernameNotFoundException("User Not Found"));
    };
}


