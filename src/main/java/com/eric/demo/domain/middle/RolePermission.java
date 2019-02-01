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
@Table(name = "sys_role_permission",indexes = {@Index(columnList = "permissionId"), @Index(columnList = "roleId")})
@org.hibernate.annotations.Table(appliesTo = "sys_role_permission", comment = "角色权限表")
public class RolePermission extends Base implements Serializable {

    private static final long serialVersionUID = 1L;

    @Column(columnDefinition = "varchar(64) COMMENT '角色id'")
    private String roleId;

    @Column(columnDefinition = "varchar(64) COMMENT '权限id'")
    private String permissionId;
}
