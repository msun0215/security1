package com.cos.security1.config.auth;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// Security 설정에서 loginProcessUrl("/login");
// login 요청이 들어오면 자동으로 UserDetailsService 타입으로
// IoC되어 있는 loadUserByUsername 함수가 실행됨
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    //@Autowired
    private UserRepository userRepository;
    //private final UserRepository userRepository;

    // Security Session = Authentication = UserDetails
    // Security Session(내부 Authentication(내부 UserDetails))
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // String username은 loginForm.html에서 넘어온 input name="username"
        User userEntity = userRepository.findByUsername(username);
        if(userEntity!=null){       // username으로 찾은 userEntity가 존재한다면
            return new PrincipalDetails(userEntity);
        }
        return null;
    }
}
