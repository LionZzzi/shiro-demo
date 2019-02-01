package com.eric.demo.controller;

import com.eric.demo.common.Result;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/error")
public class ErrorController {

    @GetMapping("/10001")
    @ResponseBody
    public Result info10001() {
        Map<String, String> map = new HashMap<>(16);
        map.put("code", "10001");
        return Result.fail(map, "token校验失败,重新登录");
    }

    @GetMapping("/10002")
    @ResponseBody
    public Result info10002() {
        Map<String, String> map = new HashMap<>(16);
        map.put("code", "10002");
        return Result.fail(map, "没有该角色的相关权限");
    }

    @GetMapping("/10003")
    @ResponseBody
    public Result info10003() {
        Map<String, String> map = new HashMap<>(16);
        map.put("code", "10003");
        return Result.fail(map, "身份校验失败");
    }
}
