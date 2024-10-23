package com.mason.security.config;

import java.io.IOException;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
//一樣有兩種方法 一個是介面實作security做好的Filter(OncePerRequestFilter)一個是繼承Filter後自己做
public class JWTAuthenticationFilter extends OncePerRequestFilter{

    private final JwtService JwtService;
    //為了讓這service能跟database連動 要自己建立一個class來實踐這個介面
    private final  UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request, 
        @NonNull HttpServletResponse response, 
        @NonNull FilterChain filterChain
    )throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        if ( authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }
        jwt = authHeader.substring(7);
        //  先做好service在進入這一步  extract userEmail from JWT token 解析token拿出username(Email)
        userEmail = JwtService.extractUsername(jwt);
        //SecurityContextHolder可以判斷使用者在Spring security是否已經被驗證過了
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if(JwtService.isTokenValid(jwt, userDetails)){
                //建立一個新的 UsernamePasswordAuthenticationToken 物件，以更新 Spring Security 中的認證資訊。
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    userDetails, 
                    null,
                    userDetails.getAuthorities()
                );
                // 為 authToken 附加來自當前 HTTP 請求的詳細資訊（如 IP 地址和會話 ID）。
                authToken.setDetails(
                    //WebAuthenticationDetailsSource().buildDetails(request) 的作用是根據當前的 HTTP 請求（request）生成一個 WebAuthenticationDetails 對象，這個對象包含了與當前會話有關的更多資訊
                    new WebAuthenticationDetailsSource().buildDetails(request)
                );
                // 將經過驗證的 authToken 放入當前的 SecurityContext 中，表示用戶已成功認證。
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        //將當前請求交給下一個過濾器
        filterChain.doFilter(request,response);
    }
    
}