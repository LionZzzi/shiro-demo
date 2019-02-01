package com.eric.demo.domain;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.List;

@EqualsAndHashCode(callSuper = true)
@Data
@NoArgsConstructor
@Entity
@Table(name = "sys_user", indexes = {@Index(columnList = "username")})
@org.hibernate.annotations.Table(appliesTo = "sys_user", comment = "用户表")
public class User extends Base {

    public User(String id) {
        this.id = id;
    }

    @Column(columnDefinition = "varchar(32) COMMENT '真实姓名'")
    private String nickname;

    @Column(nullable = false, unique = true, columnDefinition = "varchar(32) COMMENT '用户名'")
    private String username;

    @Column(nullable = false, columnDefinition = "varchar(32) COMMENT '密码'")
    private String password;

    @Column(nullable = false, columnDefinition = "int(2) COMMENT '状态 1:有效 0:冻结'")
    private Integer status = 1;

    @Transient
    private List<Role> roles;
}
