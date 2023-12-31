package com.cos.security1.config.oauth;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.FacebookUserInfo;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.NaverUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    //private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    // google로부터 받은 userRequest Data에 대한 후처리 되는 함수
    // 함수 종료시 @AuthenticationPrincipal Annotation이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {    // 후처리
        System.out.println("userRequest : "+userRequest.getClientRegistration());   // registrationId로 어떤 OAuth로 로그인했는지 확인
        System.out.println("getAccessToken : "+userRequest.getAccessToken());

        OAuth2User oAuth2User=super.loadUser(userRequest);
        // Google login button-> google login window-> Complete login
        // -> return code(OAuth-Client Library)-> Request AccessToken
        // userRequest 정보 -> loadUser함수 호출 -> Google로부터 회원 프로필을 받아줌
        //System.out.println("getAttributes : "+super.loadUser(userRequest).getAttributes());
        System.out.println("getAttributes : "+oAuth2User.getAttributes());

        OAuth2UserInfo oAuth2UserInfo=null;
        // super.loadUser를 통해서 받은 정보를 토대로 강제 회원가입 시키기
        if(userRequest.getClientRegistration().getRegistrationId().equals("google")){
            System.out.println("Google Login Try");
            oAuth2UserInfo= new GoogleUserInfo(oAuth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("facebook")){
            oAuth2UserInfo= new FacebookUserInfo(oAuth2User.getAttributes());
            System.out.println("Facebook Login Try");
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")){
            oAuth2UserInfo=new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"));
            System.out.println("Naver Login Try");
        }
        else{
            System.out.println("other login access");
        }

        // String provider=userRequest.getClientRegistration().getRegistrationId();  // Google
        String provider=oAuth2UserInfo.getProvider();   // provider가 null이면 일반로그인, 아니면 oauth로그인
        // String providerId=oAuth2User.getAttribute("sub");       // Google ID
        String providerId=oAuth2UserInfo.getProviderId();
        String username=provider+"_"+providerId;    // google_sub
        String password=bCryptPasswordEncoder.encode("겟인데어");
        //String providerEmail=oAuth2User.getAttribute("email");       // Google Email
        String providerEmail=oAuth2UserInfo.getEmail();
        String role="ROLE_USER";

        User userEntity=userRepository.findByUsername(username);

        if(userEntity==null){
            userEntity=User.builder()
                    .username(username)
                    .password(password)
                    .email(providerEmail)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
