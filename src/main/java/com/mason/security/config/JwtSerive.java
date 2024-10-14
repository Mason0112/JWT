package com.mason.security.config;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtSerive {

    private static final String  SECRET_KEY = "zFXLI934a+SzAug7VcBcpcGjLfWVyf+7SOVgNBHz/V0iI+6JzUJ9fXN/E6nT1dOQ";

    //單一參數產生出token
    public String generateToken(
        UserDetails userDetails
    ){
        return  generateToken(new HashMap<>(),userDetails);
    }
    //製作出token 我自訂的User有實作userDetails介面所以可以直接傳進來
    public String generateToken(
        Map<String,Object> extraCliams,
        UserDetails userDetails
    ){
        return Jwts
        .builder()
        .setClaims(extraCliams)
        .setSubject(userDetails.getUsername())
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis()+ 1000 *60 *24))
        .signWith(getSignInKey(),SignatureAlgorithm.HS256)
        .compact();
    }

    public boolean isTokenValid(String token , UserDetails userDetails){
        final String username = extractUsername(token);

        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));

    }
    private boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractCLaims(token, Claims::getExpiration);
    }

    public String extractUsername(String token){
        //Claims::getSubjec這方法會拿取主體中的唯一標籤 如名字或email
        return extractCLaims(token, Claims::getSubject);
    }
    //挑選extractAllClaims中所需要的部分 
    public <T>T  extractCLaims(String token, Function<Claims,T> cliamResolver){ 
        final Claims claims = extractAllClaims(token);
        return cliamResolver.apply(claims);
    }
    //解析token中的所有資訊 回傳Claims這個物件是內建的會存token中的實際資訊 ex:name email等等
    private Claims extractAllClaims(String token){
        return Jwts.parserBuilder().setSigningKey(getSignInKey()).build().parseClaimsJws(token).getBody( );
    }

    //解析上方的密鑰做成byte[] 用hmacShaKey生成HMAC-SHA 演算法的密鑰
    private Key  getSignInKey(){
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
