package com.eric.demo.controller;

import com.eric.demo.common.Result;
import com.eric.demo.domain.Permission;
import com.eric.demo.service.PermissionService;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;

@RestController
@RequestMapping("/api/permission")
public class PermissionController {

    @Resource
    private PermissionService permissionService;

    @PostMapping("/save")
    @ResponseBody
    public Result save(@RequestBody Permission permission) {
        return permissionService.save(permission);
    }
}
