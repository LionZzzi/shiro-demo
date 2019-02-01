package com.eric.demo.repository;

import com.eric.demo.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RoleRepository extends JpaRepository<Role, String> {

    List<Role> findByIdIn(List<String> roleIds);
}
