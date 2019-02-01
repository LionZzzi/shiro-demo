package com.eric.demo.module.shiro;

import com.alibaba.fastjson.JSONObject;
import com.eric.demo.common.constant.SysConstant;
import com.eric.demo.domain.Permission;
import com.eric.demo.domain.Role;
import com.eric.demo.domain.Token;
import com.eric.demo.domain.User;
import com.eric.demo.module.redis.RedisImpl;
import com.eric.demo.service.UserService;
import com.eric.demo.utils.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import javax.annotation.Resource;

@Slf4j
public class ShiroRealm extends AuthorizingRealm {

    @Resource
    private UserService userService;
    @Resource
    private RedisImpl redisImpl;

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof Token;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        // 获取登录用户名
        String username = ((User) principalCollection.getPrimaryPrincipal()).getUsername();
        // 从redis查询用户权限详情
        // Object obj = redisImpl.get(SysConstant.REDIS_PERM + username);
        User user;
        // 为空则从数据库获取
        //if (obj == null) {
        user = userService.findAllUserInfo(username);
        //} else {
         //   user = (User) obj;
        //}
        // 添加角色和权限
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        for (Role role : user.getRoles()) {
            // 添加角色
            simpleAuthorizationInfo.addRole(role.getRole());
            for (Permission permission : role.getPermissions()) {
                // 添加权限
                simpleAuthorizationInfo.addStringPermission(permission.getPermission());
            }
        }
        return simpleAuthorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        String token = (String) authenticationToken.getCredentials();
        JSONObject jsonObject = JSONObject.parseObject(JwtUtil.parse(token).getSubject());
        String username = jsonObject.getString("username");

        User user = userService.findByUsername(username);
        if (user == null) {
            //这里返回后会报出对应异常
            throw new UnknownAccountException("账号或密码错误");
        }
        if (user.getStatus() == 0) {
            throw new LockedAccountException("账号已被锁定");
        }
        //这里验证authenticationToken和simpleAuthenticationInfo的信息
        return new SimpleAuthenticationInfo(user, token, getName());

    }
}
