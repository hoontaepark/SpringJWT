package com.example.SpringJWT.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){

        return new BCryptPasswordEncoder(); //패스워드 해시암호화
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .csrf((auth) -> auth.disable()); //csrf를 disable 세션이 고정되기 떄문에 csrf 공격 필수적으로방어

        http    //JWT방식으로 로그인을 할거기때문에 폼로그인, basic 방식 disable 함
                .formLogin((auth) -> auth.disable());

        http
                .httpBasic((auth) -> auth.disable());

        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .anyRequest().authenticated());

        http
                .sessionManagement((session) -> session  //JWT는 세션을 항상 Stateless 로 관리.
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));



        return http.build();
    }
}
