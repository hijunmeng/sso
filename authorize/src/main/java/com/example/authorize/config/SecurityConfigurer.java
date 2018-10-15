package com.example.authorize.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * Created by hwj on 2018/9/10.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfigurer extends WebSecurityConfigurerAdapter {


    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .formLogin()//在浏览器能访问http://localhost:8080/oauth/authorize?client_id=client5&response_type=code&redirect_uri=http://www.baidu.com时必须添加此项，同时在ResourceServerConfigurerAdapter中也必须添加此项
                .and()
                .logout()
                .and()
                .csrf().disable();//开启csrf的话正常的post请求也会被拦截

    }
}
