package com.cos.security1.controller;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller // View를 return!
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/test/login")
    public @ResponseBody String testLogin(Authentication authentication
    , @AuthenticationPrincipal PrincipalDetails userDetails){       // Dependency Injection
        System.out.println("/test/login=========================");
        PrincipalDetails principalDetails=(PrincipalDetails)authentication.getPrincipal();
        // authentication.getPrincipal()은 Object Type
        System.out.println("authentication : "+principalDetails.getUser());

        System.out.println("userDetails : "+userDetails.getUsername());
        // @AuthenticationPrincipal로 받은 userDetails와 principlaDetails.getUser()로 받은 데이터는 동일함.
        return "Session 정보 확인하기";
    }


    @GetMapping("/test/oauth/login")
    public @ResponseBody String testOAuthLogin(Authentication authentication
            , @AuthenticationPrincipal OAuth2User oauth){       // Dependency Injection
        System.out.println("/test/oauth/login=========================");
        OAuth2User oAuth2User=(OAuth2User)authentication.getPrincipal();
        // oauth를 통해서 로그인할 경우 casting을 다르게 해야함
        // authentication.getPrincipal()은 Object Type
        System.out.println("authentication : "+oAuth2User.getAttributes());

        System.out.println("oauth2User : "+oauth.getAttributes());
        // @AuthenticationPrincipal로 받은 userDetails와 principlaDetails.getUser()로 받은 데이터는 동일함.
        return "OAuth Session 정보 확인하기";
    }

    // localhost: 8080/
    // localhost: 8080
    @GetMapping({"","/"})
    public String index(){
        // mustache 기본 폴더 : src/main/resources/
        // viewresolver 설정 : templates(prefix), .mustache(suffix) 생략 가능!
        return "index"; // src/main/resources/templates/index.mustache
    }

    // OAuth 로그인을 해도 PrincipalDetails로 받을 수 있고
    // 일반 로그인을 해도 PrincipalDetails로 받을 수 있다
    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails){
        System.out.println("principleDetails : "+principalDetails.getUser());
        return "user";
    }

    @GetMapping("/admin")
    public String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    public String manager(){
        return "manager";
    }

    // Spring Security에서 localhost:8080/login 주소를 낚아채버림!
    // SecurityConfig 파일 설정으로 해당 실행 안됨
    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @PostMapping("/join")
    public String join(User user){
        System.out.println(user);
        user.setRole("ROLE_USER");
        // 회원가입은 잘 되나 비밀번호가 1234로 저장됨
        // =>Security로 로그인을 할 수가 없음
        // Password가 Encrypt 되지 않았기 때문

        String rawPassword=user.getPassword();
        String encPassword=bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user);

        return "redirect:/loginForm";
    }

    // Secured Annotation으로 권한 부여
    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info(){
        return "개인정보";
    }

    //@PreAuthorize("ROLE_MANAGER")
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    // 권한을 하나만 부여할때는 @Secured가 편하지만
    // 여러 사람에게 권한을 부여할거면 @PreAuthorize가 더 낫다
    @GetMapping("/data")
    public @ResponseBody String data(){
        return "데이터 정보";
    }

    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }
}
