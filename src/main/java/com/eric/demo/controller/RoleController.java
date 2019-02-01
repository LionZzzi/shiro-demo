package com.eric.demo.controller;

import com.alibaba.fastjson.JSONObject;
import com.eric.demo.common.Result;
import com.eric.demo.domain.Role;
import com.eric.demo.service.RoleService;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;

@RestController
@RequestMapping("/api/role")
public class RoleController {

    @Resource
    private RoleService roleService;

    @GetMapping("/{id}")
    @ResponseBody
    public Result view(@PathVariable String id) {
        return roleService.view(id);
    }

    @PostMapping("/save")
    @ResponseBody
    public Result save(@RequestBody Role role) {
        return roleService.save(role);
    }

    @PostMapping("/addPerms/{roleId}")
    @ResponseBody
    public Result addPerms(@PathVariable String roleId, @RequestBody JSONObject permIds) {
        return roleService.addPerms(roleId, permIds);
    }
}
