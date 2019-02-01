package com.eric.demo.domain;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Transient;
import java.io.Serializable;
import java.util.List;

@EqualsAndHashCode(callSuper = true)
@Data
@NoArgsConstructor
@Entity
@Table(name = "sys_role")
@org.hibernate.annotations.Table(appliesTo = "sys_role", comment = "角色表")
public class Role extends Base implements Serializable {

    private static final long serialVersionUID = 1L;

    @Column(columnDefinition = "varchar(32) COMMENT '角色名'")
    private String role;

    @Column(columnDefinition = "varchar(512) COMMENT '描述'")
    private String description;

    @Transient
    private List<User> users;

    @Transient
    private List<Permission> permissions;
}
