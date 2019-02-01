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
@Table(name = "sys_permission")
@org.hibernate.annotations.Table(appliesTo = "sys_permission", comment = "权限表")
public class Permission extends Base implements Serializable {

    private static final long serialVersionUID = 1L;

    @Column(columnDefinition = "varchar(32) COMMENT '权限'")
    private String permission;

    @Column(nullable = false, columnDefinition = "varchar(512) COMMENT '请求uri'")
    private String uri;

    @Column(columnDefinition = "varchar(512) COMMENT '描述'")
    private String description;

    @Transient
    private List<Role> roles;
}
