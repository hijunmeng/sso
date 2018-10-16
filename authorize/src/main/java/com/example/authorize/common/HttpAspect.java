package com.example.authorize.common;

import com.example.authorize.AuthorizeApplication;
import com.example.authorize.util.Log;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.*;
import org.slf4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.net.InetAddress;

/**
 * 面向切面（AOP）实例
 * Created by HWJ on 2017/3/18.
 */
@Aspect
@Component
public class HttpAspect {

    public static final Logger logger = org.slf4j.LoggerFactory.getLogger(HttpAspect.class);

    // 定义切点Pointcut
    //表示UserController的所有方法org.springframework.security.oauth2.provider.endpoint.TokenEndpoint.postAccessToken()
    //@Pointcut("execution(public * com.junmeng.controller.UserController.*(..))")
    @Pointcut("execution(public * org.springframework.security.oauth2.provider.endpoint.TokenEndpoint.postAccessToken(..))")
    public void log() {
    }


    //拦截UserController的请求，后面的两个点表示任何参数
    //经常用来做登录验证
    //@Before("execution(public * com.junmeng.controller.UserController.*(..))")
    @Before("log()")//这种方法是减少重复的代码
    public void doBefore(JoinPoint joinPoint) {
        logger.info(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
        ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = requestAttributes.getRequest();
        logger.info("Method={}", request.getMethod());
        logger.info("RequestURI={}", request.getRequestURI());
        logger.info("RequestURL={}", request.getRequestURL());
        logger.info("PathInfo={}", request.getPathInfo());
        logger.info("ServletPath={}", request.getServletPath());
        logger.info("Protocol={}", request.getProtocol());

        //请求参数
        logger.info("QueryString= {}", request.getQueryString());
        logger.info("RequestedSessionId={}", request.getRequestedSessionId());

        logger.info("LocalAddr={}", request.getLocalAddr());
        logger.info("LocalName={}", request.getLocalName());
        logger.info("LocalPort={}", request.getLocalPort());
        logger.info("RemoteAddr={}", request.getRemoteAddr());
        logger.info("RemoteHost={}", request.getRemoteHost());
        logger.info("RemotePort={}", request.getRemotePort());

        logger.info("ContextPath={}", request.getContextPath());
        logger.info("AuthType={}", request.getAuthType());
        logger.info("ContentType={}", request.getContentType());
        logger.info("CharacterEncoding={}", request.getCharacterEncoding());

        //类方法
        logger.info("class_method={}", joinPoint.getSignature().getDeclaringTypeName() + "." + joinPoint.getSignature().getName());

        //参数
        logger.info("args={}", joinPoint.getArgs());
        logger.info("===============================================================");
    }

    //@After("execution(public * com.junmeng.controller.UserController.*(..))")
    @After("log()")
    public void doAfter() {

        logger.info("===============================================================");
    }

    /**
     * 此注解用来打印返回对象的信息，这个对于调试也是非常有用的
     *
     * @param object
     */
    @AfterReturning(returning = "object", pointcut = "log()")
    public void doAfterReturning(Object object) {

        if(!(object instanceof ResponseEntity)){
           return ;
        }
        ResponseEntity res=(ResponseEntity)object;
        if(res.getStatusCode()== HttpStatus.OK){
            Log.info("ok");
            OAuth2AccessToken token=(OAuth2AccessToken)res.getBody();
            ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            HttpServletRequest request = requestAttributes.getRequest();
            String ua=request.getHeader("User-Agent");
            String ip=getIpAddr(request);
            Log.info("ua+ip="+ua+"+"+ip);
            AuthorizeApplication.uaMap.put(ua+"+"+ip,token.getValue());
            AuthorizeApplication.tokenMap.put(token.getValue(),ua+"+"+ip);
        }
        logger.info("response={}", object == null ? "return null" : object.toString());
        logger.info("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
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