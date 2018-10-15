package com.example.authorize.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Service;

/**
 * Created by hwj on 2018/9/10.
 */
@Service
public class ClientDetailsServiceImpl implements ClientDetailsService {
    @Autowired
    PasswordEncoder passwordEncoder;

    /**
     * 注意secret需要BCrypt加密，否则会报Encoded password does not look like BCrypt
     *
     * @param s
     * @return
     * @throws ClientRegistrationException
     */
    @Override
    public ClientDetails loadClientByClientId(String s) throws ClientRegistrationException {

        BaseClientDetails bcd=null;
        if ("CA".equals(s)) {
            bcd = new BaseClientDetails(s, "", "scope", "password,refresh_token", "");//在密码模式scope仍然生效，但authorities不生效，为空即可
            bcd.setClientSecret(passwordEncoder.encode("secret"));
        }
        if ("CB".equals(s)) {
            bcd = new BaseClientDetails(s, "", "scope", "password,refresh_token", "");
            bcd.setClientSecret(passwordEncoder.encode("secret"));
        }

        return bcd;
    }
}
