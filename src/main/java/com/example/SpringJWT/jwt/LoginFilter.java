package com.example.SpringJWT.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public LoginFilter (AuthenticationManager authenticationManager){

        this.authenticationManager = authenticationManager;
    }


    @Override //인증하기 위한 메소드 authenticationManager에게 토큰전달
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        //클라이언트 요청시 username, password 를 추출함.
        //obtainUsername, Password 에 있음.
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        //username, password 검증을 위해 token에 담아야한다.
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        //username, password를 담은 토큰을 authenticationManager 에게 전달 검증하기위함
        return authenticationManager.authenticate(authToken);

    }

    //로그인 성공시 실행하는 메소드 (여기서 JWT를 발급하면 됨)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {

    }

    //로그인 실패시 실행하는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {

    }

}
