package com.eric.demo.service.impl;

import com.alibaba.fastjson.JSONObject;
import com.eric.demo.common.Result;
import com.eric.demo.domain.Role;
import com.eric.demo.domain.middle.RolePermission;
import com.eric.demo.repository.RolePermissionRepository;
import com.eric.demo.repository.RoleRepository;
import com.eric.demo.service.RoleService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class RoleServiceImpl implements RoleService {

    @Resource
    private RoleRepository roleRepository;
    @Resource
    private RolePermissionRepository rolePermissionRepository;

    @Override
    public Result view(String id) {
        Optional<Role> optionalRole = roleRepository.findById(id);
        return optionalRole.isPresent() ? Result.success(optionalRole.get(), "查询成功") : Result.fail("查询失败");
    }

    @Override
    public Result save(Role role) {
        roleRepository.save(role);
        return Result.success("新增角色成功");
    }

    @SuppressWarnings("unchecked")
    @Transactional(rollbackOn = Exception.class)
    @Override
    public Result addPerms(String roleId, JSONObject permIds) {
        Optional<Role> optionalRole = roleRepository.findById(roleId);
        if (optionalRole.isPresent()) {
            // 将permIds 转成List<String>
            List<String> list = (List<String>) permIds.get("permIds");
            List<RolePermission> rolePermissions = new ArrayList<>();
            for (String permId : list) {
                RolePermission rolePermission = new RolePermission();
                rolePermission.setRoleId(roleId);
                rolePermission.setPermissionId(permId);
                rolePermissions.add(rolePermission);
            }
            // 将数据批量插入用户角色表
            rolePermissionRepository.saveAll(rolePermissions);
            return Result.success("角色添加权限成功");
        } else {
            return Result.fail("查询不到此角色");
        }
    }
}
