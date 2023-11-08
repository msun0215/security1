package com.cos.security1;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class Security1Application {

	@Bean   // @Bean의 역할은 해당 메서드의 return 되는 Object를 IoC로 등록해줌
	public BCryptPasswordEncoder encodePwd(){
		return new BCryptPasswordEncoder();
	}
	public static void main(String[] args) {
		SpringApplication.run(Security1Application.class, args);
	}

}
