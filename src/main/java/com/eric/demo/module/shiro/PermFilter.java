package com.eric.demo.module.shiro;

import org.apache.shiro.web.filter.authz.PermissionsAuthorizationFilter;

public class PermFilter extends PermissionsAuthorizationFilter {
    //TODO: 有需求可以自己重写isAccessAllowed,参考RoleFilter
}
