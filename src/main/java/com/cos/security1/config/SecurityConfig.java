package com.cos.security1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdaper;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/*
@Configuration
@EnableWebSecurity  // Spring Security Filter가 Spring FilterChain에 등록이 된다.
public class SecurityConfig extends WebSecurityConfigurerAdapter{
}
*/


/*
스프링 시큐리티를 사용하면 기본적인 시큐리티 설정을 하기 위해서
WebSecurityConfigurerAdapter라는 추상 클래스를 상속하고,
configure 메서드를 오버라이드하여 설정하였습니다.
그러나 스프링 시큐리티 5.7.0-M2 부터 WebSecurityConfigurerAdapter는
deprecated 되었습니다.


스프링 공식 블로그 2022년 2월 21일 글에서 WebSecurityConfigurerAdapter를
사용하는 것을 권장하지 않는다고 컴포넌트 기반 설정으로 변경할것을 권항합니다.

스프링 부트 2.7.0 이상의 버전을 사용하면 스프링 시큐리티 5.7.0 혹은
이상의 버전과 의존성이 있습니다.
그렇다면 WebSecurityConfigurerAdapter가 deprecated 된 것을 확인할 수 있습니다.
현재 스프링 부트 3와 의존관계인 스프링 시큐리티6에서는 WebSecurityConfigurerAdapter
클래스가 제거되었습니다.
스프링 부트 혹은 스프링 시큐리티 버전을 높이기 위해서라면
WebSecurityConfigurerAdapter deprecated 된 설정을 제거해야 합니다.
 */


@Configuration
@EnableWebSecurity  // Spring Security Filter가 Spring FilterChain에 등록이 된다.
public class SecurityConfig{

    @Bean   // @Bean의 역할은 해당 메서드의 return 되는 Object를 IoC로 등록해줌
    public BCryptPasswordEncoder encodePwd(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(CsrfConfigurer::disable);
        http.authorizeHttpRequests(authorize ->
                authorize
                        .requestMatchers("/user/**").authenticated()
                        .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers("/admin/**").hasAnyRole("ADMIN")

                        .anyRequest().permitAll()
        ).formLogin(formLogin->{
            formLogin.loginPage("/loginForm")
                    .loginProcessingUrl("/login")
                    // /login 주소가 호출이 되면 Security가 낚아채서 대신 로그인을 진행해준다.
                    .defaultSuccessUrl("/");
        });
        // /user, /manager, /admin으로 들어가도 /loginForm으로 접근하도록
        return http.build();
    }

    /*
    기존: WebSecurityConfigurerAdapter를 상속하고 configure매소드를 오버라이딩하여 설정하는 방법
    => 현재: SecurityFilterChain을 리턴하는 메소드를 빈에 등록하는 방식(컴포넌트 방식으로 컨테이너가 관리)
    //https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter

    @Override
    protected void configure(HttpSecurity http) throws  Exception{
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin").access("\"hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();
    }

     */
}