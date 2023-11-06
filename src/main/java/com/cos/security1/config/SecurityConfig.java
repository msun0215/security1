package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
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
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
// Secured Annotation 활성화, preAuthorize Annotation 활성화
public class SecurityConfig{

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;
    @Bean   // @Bean의 역할은 해당 메서드의 return 되는 Object를 IoC로 등록해줌
    public BCryptPasswordEncoder encodePwd(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(CsrfConfigurer::disable);
        http.authorizeHttpRequests(authorize ->
                authorize
                        .requestMatchers("/user/**").authenticated()    // 인증만 되면 들어갈 수 있는 주소
                        .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers("/admin/**").hasAnyRole("ADMIN")

                        .anyRequest().permitAll()
        ).formLogin(formLogin->{
            formLogin.loginPage("/loginForm")
                    .loginProcessingUrl("/login")
                    // /login 주소가 호출이 되면 Security가 낚아채서 대신 로그인을 진행해준다.
                    .defaultSuccessUrl("/");
        }).oauth2Login(httpSecurityOAuth2LoginConfigurer -> {
            httpSecurityOAuth2LoginConfigurer.loginPage("/loginForm")
            // google login이 완료된 뒤의 후처리가 필요함
            // 1. 코드받기(인증)-> 2. 엑세스토큰(권한)->
            // 3. 사용자 프로필 정보를 가져오고-> 4-1. 그 정보를 토대로 회원가입을 자동으로 진행시키기도 함
            // 4-2. (이메일, 전화번호, 이름, 아이디)쇼핑몰 -> (집주소)
            //      백화점몰 -> (vip등급/일반등급)
            // Tip. 코드 X, (Access Token+사용자 프로필 정보 O)
            .userInfoEndpoint(userInfoEndpointConfig -> {
                userInfoEndpointConfig.userService(principalOauth2UserService);
            });
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