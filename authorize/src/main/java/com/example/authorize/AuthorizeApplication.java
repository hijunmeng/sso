package com.example.authorize;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashMap;


@SpringBootApplication
public class AuthorizeApplication {
	public static HashMap<String, String> uaMap = new HashMap<String, String>();
	public static HashMap<String, String> tokenMap = new HashMap<String, String>();
	public static void main(String[] args) {
		SpringApplication.run(AuthorizeApplication.class, args);
	}
	@Bean
	public PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}
}
