package com.eric.demo.repository;

import com.eric.demo.domain.middle.RolePermission;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RolePermissionRepository extends JpaRepository<RolePermission, String> {

    List<RolePermission> findByRoleId(String roleId);

    List<RolePermission> findByPermissionId(String permissionId);
}
