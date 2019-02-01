package com.eric.demo.repository;

import com.eric.demo.domain.Permission;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PermissionRepository extends JpaRepository<Permission, String> {

    List<Permission> findByIdIn(List<String> permissionIds);
}
