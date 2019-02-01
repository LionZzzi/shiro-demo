package com.eric.demo.repository;

import com.eric.demo.domain.middle.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface UserRoleRepository extends JpaRepository<UserRole, String> {

    List<UserRole> findByUserId(String userId);

    List<UserRole> findByRoleId(String roleId);
}
