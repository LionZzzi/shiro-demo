package com.eric.demo.utils;

import org.apache.commons.lang3.StringUtils;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class WebApplicationUtil {

    /**
     * 获取请求的token
     */
    public static String getToken(ServletRequest httpRequest) {
        HttpServletRequest request = (HttpServletRequest) httpRequest;
        // 从header中获取token
        String token = request.getHeader("token");
        // 如果header中不存在token，则从参数中获取token
        if (StringUtils.isBlank(token)) {
            token = httpRequest.getParameter("token");
        }
        return token;
    }

    public static void returnInfo(String code, ServletResponse response) throws IOException {
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        String url = String.format("/api/error/%s", code);
        httpServletResponse.sendRedirect(url);
    }

    static <T> T getBean(Class<T> clazz, HttpServletRequest request) {
        //通过该方法获得的applicationContext 已经是初始化之后的applicationContext 容器
        WebApplicationContext applicationContext = WebApplicationContextUtils.getRequiredWebApplicationContext(request.getServletContext());
        return applicationContext.getBean(clazz);
    }
}
