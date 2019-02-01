package com.eric.demo.controller;

import com.alibaba.fastjson.JSONObject;
import com.eric.demo.common.Result;
import com.eric.demo.domain.User;
import com.eric.demo.service.UserService;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @Resource
    private UserService userService;

    @GetMapping("/{id}")
    @ResponseBody
    public Result view(@PathVariable String id) {
        return userService.view(id);
    }

    @PostMapping("/save")
    @ResponseBody
    public Result save(@RequestBody User user) {
        return userService.save(user);
    }

    @PostMapping("/addRoles/{userId}")
    @ResponseBody
    public Result addRoles(@PathVariable String userId, @RequestBody JSONObject roleIds) {
        return userService.addRoles(userId, roleIds);
    }
}
