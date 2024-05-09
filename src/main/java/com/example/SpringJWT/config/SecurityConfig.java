package com.example.SpringJWT.config;


import com.example.SpringJWT.jwt.LoginFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    //Authentication 생성자 생성
    //AuthenticationFilter에 인자를 전달하기 위해 생성자 만듦.
    private final AuthenticationConfiguration authenticationConfiguration;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration){

        this.authenticationConfiguration = authenticationConfiguration;
    }

    //AuthenticationManager Bean 등록
    //애가 토큰검증하는 Bean임.
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }
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

        //jwt 토큰방식 로그인 설정, authenticationFilter 추가함.
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration)), UsernamePasswordAuthenticationFilter.class);

        http
                .sessionManagement((session) -> session  //JWT는 세션을 항상 Stateless 로 관리.
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));



        return http.build();
    }
}
