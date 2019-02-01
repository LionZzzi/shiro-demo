package com.eric.demo.service;

import com.alibaba.fastjson.JSONObject;
import com.eric.demo.common.Result;
import com.eric.demo.domain.User;

public interface UserService {

    /**
     * 保存用户
     *
     * @param user User
     * @return Result
     */
    Result save(User user);

    /**
     * 根据id查看用户
     *
     * @param id 用户id
     * @return Result
     */
    Result view(String id);

    /**
     * 用户添加角色
     *
     * @param userId  用户id
     * @param roleIds 角色id(可以多个或一个)
     * @return Result
     */
    Result addRoles(String userId, JSONObject roleIds);

    /**
     * 根据用户名查找用户全部信息
     *
     * @param username String
     * @return User
     */
    User findAllUserInfo(String username);

    /**
     * 根据用户名查找用户
     *
     * @param username String
     * @return User
     */
    User findByUsername(String username);

}
