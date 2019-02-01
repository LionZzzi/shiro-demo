package com.eric.demo.domain.middle;

import com.eric.demo.domain.Base;
import lombok.Data;
import lombok.EqualsAndHashCode;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Index;
import javax.persistence.Table;
import java.io.Serializable;

@EqualsAndHashCode(callSuper = true)
@Data
@Entity
@Table(name = "sys_user_role", indexes = {@Index(columnList = "userId"), @Index(columnList = "roleId")})
@org.hibernate.annotations.Table(appliesTo = "sys_user_role", comment = "用户角色表")
public class UserRole extends Base implements Serializable {

    private static final long serialVersionUID = 1L;

    @Column(columnDefinition = "varchar(64) COMMENT '用户id'")
    private String userId;

    @Column(columnDefinition = "varchar(64) COMMENT '角色id'")
    private String roleId;
}
