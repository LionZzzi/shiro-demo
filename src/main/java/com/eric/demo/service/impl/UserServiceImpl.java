package com.eric.demo.service.impl;

import com.alibaba.fastjson.JSONObject;
import com.eric.demo.common.Result;
import com.eric.demo.common.constant.SysConstant;
import com.eric.demo.domain.Permission;
import com.eric.demo.domain.Role;
import com.eric.demo.domain.User;
import com.eric.demo.domain.middle.RolePermission;
import com.eric.demo.domain.middle.UserRole;
import com.eric.demo.module.redis.RedisImpl;
import com.eric.demo.repository.*;
import com.eric.demo.service.UserService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    @Resource
    private UserRepository userRepository;
    @Resource
    private RoleRepository roleRepository;
    @Resource
    private PermissionRepository permissionRepository;
    @Resource
    private UserRoleRepository userRoleRepository;
    @Resource
    private RolePermissionRepository rolePermissionRepository;
    @Resource
    private RedisImpl redisImpl;

    @Override
    public Result save(User user) {
        userRepository.save(user);
        return Result.success("新增用户成功");
    }

    @Override
    public User findAllUserInfo(String username) {
        // 通过username 查找 User
        User user = userRepository.findByUsername(username);
        // 通过userId 获取 userRoles
        List<UserRole> userRoles = userRoleRepository.findByUserId(user.getId());
        List<String> roleIds = new ArrayList<>();
        // 遍历userRoles 获取List<String> roleIds
        for (UserRole userRole : userRoles) {
            roleIds.add(userRole.getRoleId());
        }
        // 通过roleRepository.findByIdIn(roleIds) 获取List<Role>
        List<Role> roles = roleRepository.findByIdIn(roleIds);

        // 原理同上，结果就是把permission添加到role里面
        for (Role role : roles) {
            List<RolePermission> rolePermissions = rolePermissionRepository.findByRoleId(role.getId());
            List<String> permissionIds = new ArrayList<>();
            for (RolePermission rolePermission : rolePermissions) {
                permissionIds.add(rolePermission.getPermissionId());
            }
            List<Permission> permissions = permissionRepository.findByIdIn(permissionIds);
            role.setPermissions(permissions);
        }
        //  将List<Role>插入user中
        user.setRoles(roles);
        //  将用户权限信息放入缓存,过期时间为3小时
        // redisImpl.set(SysConstant.REDIS_PERM + user.getUsername(), user, SysConstant.EXPIRE_TIME * 6);
        return user;
    }

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public Result view(String id) {
        Optional<User> optionalUser = userRepository.findById(id);
        return optionalUser.isPresent() ? Result.success(optionalUser.get(), "查询成功") : Result.fail("查询失败");
    }

    @SuppressWarnings("unchecked")
    @Transactional(rollbackOn = Exception.class)
    @Override
    public Result addRoles(String userId, JSONObject roleIds) {
        Optional<User> optionalUser = userRepository.findById(userId);
        if (optionalUser.isPresent()) {
            // 将roleIds 转成List<String>
            List<String> list = (List<String>) roleIds.get("roleIds");
            List<UserRole> userRoles = new ArrayList<>();
            for (String roleId : list) {
                UserRole userRole = new UserRole();
                userRole.setRoleId(roleId);
                userRole.setUserId(userId);
                userRoles.add(userRole);
            }
            // 将数据批量插入用户角色表
            userRoleRepository.saveAll(userRoles);
            return Result.success("添加角色成功");
        } else {
            return Result.fail("查询不到此用户");
        }
    }
}
