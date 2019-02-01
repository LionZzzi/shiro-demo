package com.eric.demo.module.shiro;

import com.eric.demo.domain.Token;
import com.eric.demo.utils.JwtUtil;
import com.eric.demo.utils.WebApplicationUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

@Slf4j
public class ShiroFilter extends BasicHttpAuthenticationFilter {

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        if (JwtUtil.verify(request, response)) {
            try {
                executeLogin(request, response);
                return true;
            } catch (Exception e) {
                log.error("身份校验失败");
                try {
                    WebApplicationUtil.returnInfo("10003", response);
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        }
        return false;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest servletRequest, ServletResponse servletResponse) throws IOException {
        WebApplicationUtil.returnInfo("10001", servletResponse);
        return false;
    }

    @Override
    protected boolean executeLogin(ServletRequest request, ServletResponse response) {
        String headToken = WebApplicationUtil.getToken(request);
        Token token = new Token(headToken);
        this.getSubject(request, response).login(token);
        return true;
    }
}
