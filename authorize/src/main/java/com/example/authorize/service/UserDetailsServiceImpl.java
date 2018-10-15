package com.example.authorize.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.HashSet;

/**
 * Created by hwj on 2018/9/10.
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    PasswordEncoder passwordEncoder;

    /**
     * 注意password需要BCrypt加密，否则会报Encoded password does not look like BCrypt
     * 授权的时候是对角色授权，而认证的时候应该基于资源，而不是角色，因为资源是不变的，而用户的角色是会变的
     * 因此这里授予的是用户的资源权限而非角色（角色是变化的，而系统的资源是固定的）
     *
     * @param s
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        //这里实际的做法应该是从数据库获取用户的权限信息
        User user = null;
        if ("UA".equalsIgnoreCase(s)) {
            user = mockAdmin();
        } else if("UB".equalsIgnoreCase(s)) {
            user = mockUser();
        }else{
            throw new UsernameNotFoundException("用户不存在");
        }

        return user;
    }


    private User mockAdmin() {
        Collection<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("res1"));//用户所拥有权限,注意不是角色
        authorities.add(new SimpleGrantedAuthority("res2"));//用户所拥有权限,注意不是角色
        authorities.add(new SimpleGrantedAuthority("res3"));//用户所拥有权限,注意不是角色
        User user = new User("UA", passwordEncoder.encode("123456"), authorities);

        return user;
    }

    private User mockUser() {
        User user = new User("UB", passwordEncoder.encode("123456"), AuthorityUtils.commaSeparatedStringToAuthorityList("res1,res2"));
        return user;
    }


}
