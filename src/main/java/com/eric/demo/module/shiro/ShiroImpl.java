package com.eric.demo.module.shiro;

import com.eric.demo.domain.Permission;
import com.eric.demo.repository.PermissionRepository;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class ShiroImpl {

    @Resource
    private PermissionRepository permissionRepository;

    public Map<String, String> loadFilterChainDefinitions() {
        List<Permission> permissions = permissionRepository.findAll();
        // 权限控制map.从数据库获取
        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
        for (Permission permission : permissions) {
            // noSessionCreation的作用是用户在操作session时会抛异常
            filterChainDefinitionMap.put(permission.getUri(), "noSessionCreation,jwt,perms[" + permission.getPermission() + "]");
        }

        //region 设置swagger接口文档访问权限 生产环境下启用
//        filterChainDefinitionMap.put("/swagger-ui.html","jwt,roles[super_admin]");
//        filterChainDefinitionMap.put("/swagger-resources/**", "jwt,roles[super_admin]");
//        filterChainDefinitionMap.put("/v2/api-docs", "jwt,roles[super_admin]");
//        filterChainDefinitionMap.put("/webjars/springfox-swagger-ui/**", "jwt,roles[super_admin]");
        //endregion

        filterChainDefinitionMap.put("/api/login", "anon");
        filterChainDefinitionMap.put("/api/error/**", "anon");
        filterChainDefinitionMap.put("/api/test/view", "noSessionCreation,jwt,perms[test-view]");
        filterChainDefinitionMap.put("/api/test/add", "noSessionCreation,jwt,perms[test-add]");
        filterChainDefinitionMap.put("/api/logout", "anon");
        // 配置全局过滤
        filterChainDefinitionMap.put("/**", "noSessionCreation,jwt");
        return filterChainDefinitionMap;
    }

    public void updatePermission(ShiroFilterFactoryBean shiroFilterFactoryBean) {
        synchronized (this) {
            AbstractShiroFilter shiroFilter;
            try {
                shiroFilter = (AbstractShiroFilter) shiroFilterFactoryBean.getObject();
            } catch (Exception e) {
                throw new RuntimeException("get ShiroFilter from shiroFilterFactoryBean error!");
            }

            PathMatchingFilterChainResolver filterChainResolver = (PathMatchingFilterChainResolver) shiroFilter.getFilterChainResolver();
            DefaultFilterChainManager manager = (DefaultFilterChainManager) filterChainResolver.getFilterChainManager();

            // 清空老的权限控制
            manager.getFilterChains().clear();

            shiroFilterFactoryBean.getFilterChainDefinitionMap().clear();
            shiroFilterFactoryBean.setFilterChainDefinitionMap(loadFilterChainDefinitions());
            // 重新构建生成
            Map<String, String> chains = shiroFilterFactoryBean.getFilterChainDefinitionMap();
            for (Map.Entry<String, String> entry : chains.entrySet()) {
                String url = entry.getKey();
                String chainDefinition = entry.getValue().trim()
                        .replace(" ", "");
                manager.createChain(url, chainDefinition);
            }
        }
    }
}
