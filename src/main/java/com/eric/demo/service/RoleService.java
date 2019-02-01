package com.eric.demo.service;

import com.alibaba.fastjson.JSONObject;
import com.eric.demo.common.Result;
import com.eric.demo.domain.Role;

public interface RoleService {
    Result view(String id);

    Result save(Role role);

    Result addPerms(String roleId, JSONObject permIds);
}
