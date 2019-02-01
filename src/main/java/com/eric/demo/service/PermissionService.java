package com.eric.demo.service;

import com.eric.demo.common.Result;
import com.eric.demo.domain.Permission;

public interface PermissionService {
    Result save(Permission permission);
}
