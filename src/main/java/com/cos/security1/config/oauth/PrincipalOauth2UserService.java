package com.cos.security1.config.oauth;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    // google로부터 받은 userRequest Data에 대한 후처리 되는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {    // 후처리
        System.out.println("userRequest : "+userRequest.getClientRegistration());   // registrationId로 어떤 OAuth로 로그인했는지 확인
        System.out.println("getAccessToken : "+userRequest.getAccessToken());
        // Google login button-> google login window-> Complete login
        // -> return code(OAuth-Client Library)-> Request AccessToken
        // userRequest 정보 -> loadUser함수 호출 -> Google로부터 회원 프로필을 받아줌
        System.out.println("getAttributes : "+super.loadUser(userRequest).getAttributes());

        OAuth2User oAuth2User=super.loadUser(userRequest);
        // super.loadUser를 통해서 받은 정보를 토대로 강제 회원가입 시키기
        return super.loadUser(userRequest);
    }
}
