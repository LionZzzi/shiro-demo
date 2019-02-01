package com.eric.demo.module.shiro;

import com.eric.demo.utils.WebApplicationUtil;
import io.jsonwebtoken.lang.Collections;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authz.RolesAuthorizationFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.List;

@Slf4j
public class RoleFilter extends RolesAuthorizationFilter {

    @SuppressWarnings("unchecked")
    @Override
    public boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        Subject subject = getSubject(request, response);
        String[] rolesArray = (String[]) mappedValue;
        if (rolesArray == null || rolesArray.length == 0) {
            return true;
        }
        for (String role : rolesArray) {
            List<String> roleList = Collections.arrayToList(role.split(":"));
            for (String o : roleList) {
                if (subject.hasRole(o)) {
                    return true;
                }
            }
        }
        return false;

    }

    /**
     * 权限校验失败，错误处理
     */
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws IOException {
        WebApplicationUtil.returnInfo("10002", response);
        return false;
    }

}
