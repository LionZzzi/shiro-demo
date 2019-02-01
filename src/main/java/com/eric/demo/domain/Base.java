package com.eric.demo.domain;

import lombok.Data;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

@Data
@MappedSuperclass
public class Base implements Serializable {

    public static final long serialVersionUID = 1L;

    @Id
    @Column(name = "id", columnDefinition = "varchar(64) COMMENT '主键'")
    @GenericGenerator(name = "uuid", strategy = "uuid2")
    @GeneratedValue(generator = "uuid")
    public String id;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(nullable = false, updatable = false, columnDefinition = "datetime COMMENT '创建时间'")
    public Date createTime;


    @Temporal(TemporalType.TIMESTAMP)
    @Column(nullable = false, columnDefinition = "datetime COMMENT '修改时间'")
    public Date updateTime;


    @PrePersist
    public void onCreate() {
        createTime = updateTime = new Date();
    }

    @PreUpdate
    public void onUpdate() {
        this.updateTime = new Date();
    }
}
