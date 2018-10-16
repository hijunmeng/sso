package com.example.authorize.web;

import com.example.authorize.AuthorizeApplication;
import com.example.authorize.util.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by hwj on 2018/9/16.
 */

@RestController
public class AuthorizeController {
    @Autowired
    RestTemplate restTemplate;
    @Value("${server.port}")
    String port;
    @Autowired
    ConsumerTokenServices consumerTokenServices;



    /**
     * 销毁access_token
     *
     * @param token
     * @return
     */
    @GetMapping("/oauth/revoke_token")
    public String revokeToken(@RequestParam String token) {
        //退出登录时要把同台电脑的其他系统的token也移除
        //销毁token的同时也要从tokenMap移除
        Log.info("tokenMap移除前size="+AuthorizeApplication.tokenMap.size());
        AuthorizeApplication.tokenMap.remove(token);
        Log.info("tokenMap移除后size="+AuthorizeApplication.tokenMap.size());
        if (consumerTokenServices.revokeToken(token)) {
            return "{\"result\":true}";
        } else {
            return "{\"result\":false}";
        }
    }


    @PostMapping("/oauth/sso")
    public String sso(
            HttpServletRequest request
            , @RequestParam String clientId
            , @RequestParam String clientSecret
    ) {
        String ua = request.getHeader("User-Agent");
        Log.info("User-Agent:" + ua);
        if (ua == null) {
            return "ua为空";
        }
        String ip = getIpAddr(request);
        Log.info("ip:" + ip);

        String username = AuthorizeApplication.uaMap.get(ua + "+" + ip);
        if (username == null) {//
            //空着返回
            return "没有已登录用户";
        }
        //不为空则表示已有用户登录，那么则根据用户名查找用户密码进行登录
        //此处为了演示直接硬编码了密码123456

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> variable = new LinkedMultiValueMap<>();
        variable.set("username", username);
        variable.set("password", "123456");
        variable.set("client_id", clientId);
        variable.set("client_secret", clientSecret);
        variable.set("grant_type", "password");
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(variable, headers);
        ResponseEntity<String> res = restTemplate.postForEntity("http://localhost:\"+port+\"/oauth/token", entity, String.class);
        if (res.getStatusCode() == HttpStatus.OK) {
            //登录成功则把ua+ip存进uaMap
            //uaMap.put()
           // String dd=res.getBody()
            return res.getBody();
        }
        return "";
    }


    /**
     * 获取用户凭证（供客户端使用）
     *
     * @param principal
     * @return
     */
    @GetMapping("/user")
    public Principal user(HttpServletRequest request, Principal principal) {
        getIpAddr(request);
        return principal;
    }

    /**
     * @Description: 获取客户端IP地址
     */
    private String getIpAddr(HttpServletRequest request) {
        String ip = request.getHeader("x-forwarded-for");
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
            if (ip.equals("127.0.0.1")) {
                //根据网卡取本机配置的IP
                InetAddress inet = null;
                try {
                    inet = InetAddress.getLocalHost();
                } catch (Exception e) {
                    e.printStackTrace();
                }
                ip = inet.getHostAddress();
            }
        }
        // 多个代理的情况，第一个IP为客户端真实IP,多个IP按照','分割
        if (ip != null && ip.length() > 15) {
            if (ip.indexOf(",") > 0) {
                ip = ip.substring(0, ip.indexOf(","));
            }
        }
        return ip;
    }

}
