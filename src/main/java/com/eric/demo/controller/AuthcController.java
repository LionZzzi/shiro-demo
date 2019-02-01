package com.eric.demo.controller;

import com.eric.demo.common.Result;
import com.eric.demo.common.constant.SysConstant;
import com.eric.demo.domain.User;
import com.eric.demo.module.redis.RedisImpl;
import com.eric.demo.service.UserService;
import com.eric.demo.utils.JwtUtil;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Eric
 */
@RestController
public class AuthcController {

    @Resource
    private UserService userService;
    @Resource
    private RedisImpl redisImpl;

    @PostMapping("/api/login")
    @ResponseBody
    public Result login(@RequestBody User user, HttpServletResponse response) throws JsonProcessingException {
        User u = userService.findByUsername(user.getUsername());
        if (u == null || u.getStatus() == 0) {
            return Result.fail("错误");
        }
        u.setPassword(null);
        // 实体类转json字符串,null字段不参与序列化
        String token = JwtUtil.create(new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL).writeValueAsString(u));
        response.setHeader("token", token);
        // 存入redis,因为实体表的username为unique,所以把username当成key(id也行,但是后续代码要自己改) 默认1个小时过期
        redisImpl.set(SysConstant.REDIS_TOKEN + u.getUsername(), token, SysConstant.EXPIRE_TIME * 2);
        return Result.success(token, "登录成功");
    }
}
