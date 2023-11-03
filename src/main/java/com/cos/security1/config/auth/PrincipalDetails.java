package com.cos.security1.config.auth;

// Security가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다
// login을 진행이 완료가 되면 Security Session을 만들어 준다(Security ContextHolder)
// Object Type => Authentication Type Object
// Authentication 안에 User의 정보가 있어야 함
// User Object Type => UserDetails Type Object

import com.cos.security1.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

// Security Session=> Authentication => UserDetails(PrincipalDetails)
public class PrincipalDetails implements UserDetails {

    private User user;  // Composition

    public PrincipalDetails(User user){
        this.user=user;
    }

    // 해당 User의 권한을 return하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // User의 Roll을 return하는데, User.getRoll()의 타입은 String
        Collection<GrantedAuthority> collect=new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 계정 만료되지 않았는가?
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 계정이 잠기지 않았는가?
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // user의 비밀번호가 기간이 지났는가?
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 계정이 활성화 되어있는가?
    @Override
    public boolean isEnabled() {

        // 비활성화가 되는 경우
        //

        return true;
    }
}
