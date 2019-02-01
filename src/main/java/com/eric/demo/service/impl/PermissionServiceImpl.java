package com.eric.demo.service.impl;

import com.eric.demo.common.Result;
import com.eric.demo.domain.Permission;
import com.eric.demo.module.shiro.ShiroImpl;
import com.eric.demo.repository.PermissionRepository;
import com.eric.demo.service.PermissionService;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

@Service
public class PermissionServiceImpl implements PermissionService {

    @Resource
    private ShiroFilterFactoryBean shiroFilterFactoryBean;
    @Resource
    private ShiroImpl shiroImpl;
    @Resource
    private PermissionRepository permissionRepository;

    @Override
    public Result save(Permission permission) {
        permissionRepository.save(permission);
        shiroImpl.updatePermission(shiroFilterFactoryBean);
        return Result.success("权限添加成功");
    }
}
