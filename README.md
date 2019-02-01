# shiro-demo
#前言
趁着年底没事做就自己搞了个后台权限框架玩玩.
**本项目没有经过很严谨的测试**,但是主要功能都实现了.
如果出现了什么严重的bug或者有更好的实现方法请联系我,我会第一时间解决和完善,谢谢ღ
**源码在文章底部**
#环境配置
1.jdk 1.8
2.mysql 5.7.24
3.redis
#运行
1.自行安装mysql,创建demo数据库,执行项目里sql下的demo.sql
2.将项目导入idea,自己修改配置
#主要技术实现
**token过期重新签发**
```
        public static Boolean verify(ServletRequest request, ServletResponse response) {
        // 获取头部的token信息
        String token = WebApplicationUtil.getToken(request);
        // 判断token是否为空
        if (StringUtils.isNotBlank(token)) {
            String username = getUsername(token);
            RedisImpl redisImpl = WebApplicationUtil.getBean(RedisImpl.class, (HttpServletRequest) request);
            // 进入redis查询是否还存活
            Object o = redisImpl.get(SysConstant.REDIS_TOKEN + username);
            if (o != null && token.equals(o.toString())) {
                HttpServletResponse httpServletResponse = (HttpServletResponse) response;
                try {
                    // 解析token,过期token则抛出ExpiredJwtException异常
                    JwtUtil.parse(token);
                    httpServletResponse.setHeader("token", token);
                } catch (ExpiredJwtException e) {
                    // 大于jwt token过期时间小于redis的存活时间,则允许重新签发一个新的token,并重置redis的存活时间
                    UserService userService = WebApplicationUtil.getBean(UserService.class, (HttpServletRequest) request);
                    User user = userService.findByUsername(username);
                    user.setPassword(null);
                    try {
                        String newToken = JwtUtil.create(new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL).writeValueAsString(user));
                        redisImpl.set(SysConstant.REDIS_TOKEN + username, newToken, SysConstant.EXPIRE_TIME * 2);
                        httpServletResponse.setHeader("token", newToken);
                    } catch (JsonProcessingException e1) {
                        e1.printStackTrace();
                    }
                }
                // 没过期则继续进行流程
                return true;
            }
        }
        return false;
    }
```
以上代码的实现思路就是token过期时间半小时,redis过期时间为1小时.
大致的流程已画出来
![QQ截图20190201222332.png](https://upload-images.jianshu.io/upload_images/16056606-7abcb0d0093ba0a0.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
---
**重写拦截器**
```
public class ShiroFilter extends BasicHttpAuthenticationFilter {

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        if (JwtUtil.verify(request, response)) {
            try {
                executeLogin(request, response);
                return true;
            } catch (Exception e) {
                log.error("身份校验失败");
                try {
                    WebApplicationUtil.returnInfo("10003", response);
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        }
        return false;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest servletRequest, ServletResponse servletResponse) throws IOException {
        WebApplicationUtil.returnInfo("10001", servletResponse);
        return false;
    }

    @Override
    protected boolean executeLogin(ServletRequest request, ServletResponse response) {
        String headToken = WebApplicationUtil.getToken(request);
        Token token = new Token(headToken);
        this.getSubject(request, response).login(token);
        return true;
    }
}
```

请求接口,一开始进入isAccessAllowed判断token,如果正确则执行executeLogin -> ShiroRealm.AuthenticationInfo,错误则执行onAccessDenied.感觉都很简单没啥好讲解的....

--- 
**自定义角色拦截器**
RoleFilter
```
public class RoleFilter extends RolesAuthorizationFilter {

    @SuppressWarnings("unchecked")
    @Override
    public boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        Subject subject = getSubject(request, response);
        String[] rolesArray = (String[]) mappedValue;
        if (rolesArray == null || rolesArray.length == 0) {
            return true;
        }
        for (String role : rolesArray) {
            List<String> roleList = Collections.arrayToList(role.split(":"));
            for (String o : roleList) {
                if (subject.hasRole(o)) {
                    return true;
                }
            }
        }
        return false;

    }

    /**
     * 权限校验失败，错误处理
     */
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws IOException {
        WebApplicationUtil.returnInfo("10002", response);
        return false;
    }

}
```
[shiro 官方默认拦截器](http://shiro.apache.org/web.html#Web-DefaultFilters)
shiro本来的角色拦截器需要同时拥有全部角色才通过,但是这并不符合我们的需求,所以重写成 或 关系即可.
大概思路就是存在一个角色即通过(这段代码写得有点烂,但是懒得重构了)
之后在ShiroConfig写入拦截器
```
    @Bean
    public ShiroFilterFactoryBean shirFilter(SecurityManager securityManager, ShiroImpl shiroImpl) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        // 自定义 ShiroFilter 过滤器，替代默认的过滤器
        Map<String, Filter> filters = shiroFilterFactoryBean.getFilters();
        filters.put("jwt", new ShiroFilter());
        filters.put("roleOr", new RoleFilter());
        shiroFilterFactoryBean.setFilters(filters);

        shiroFilterFactoryBean.setFilterChainDefinitionMap(shiroImpl.loadFilterChainDefinitions());
        return shiroFilterFactoryBean;
    }
```
---
**动态权限刷新**
```
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
```
因为这一段代码也是在网上参考别人的,大致的意思就是项目启动执行loadFilterChainDefinitions方法,之后去数据库查询权限拼装返回ShiroConfig.shiroFilter放入shiro拦截器里.

updatePermission这段代码的意思就是清空旧的拦截器注入新的,具体使用在PermissionServiceImpl里

---

#测试
在ShiroImpl.loadFilterChainDefinitions中写入以下代码用户测试
```
filterChainDefinitionMap.put("/api/test/view", "noSessionCreation,jwt,perms[test-view]");
filterChainDefinitionMap.put("/api/test/add", "noSessionCreation,jwt,perms[test-add]");
```
用户eric拥有vip角色具有test-add的权限
**登录**
![QQ截图20190201225924.png](https://upload-images.jianshu.io/upload_images/16056606-842e53a50273026a.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

**测试添加接口**
带着token访问
![QQ截图20190201230059.png](https://upload-images.jianshu.io/upload_images/16056606-855f07aca4c6c584.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
正确的返回结果(不带token访问请自行测试,太麻烦了,懒得在贴图了...)

**测试查看接口**
带着token访问
![测试查看接口.png](https://upload-images.jianshu.io/upload_images/16056606-bca4af7a7539a6f3.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
因为没有查看的权限,所以Unauthorized.
可自定义返回接口信息,因为太懒了,所以这段就没写自定义返回信息.但是代码里有实现这个功能

**添加权限**
带着token访问
![添加权限.png](https://upload-images.jianshu.io/upload_images/16056606-9e73c8ddbdde5dfd.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

**角色添加权限**
带着token访问
![角色添加权限.png](https://upload-images.jianshu.io/upload_images/16056606-b132966acad30cf5.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

**测试添加权限后的查看接口**
带着token访问
![测试添加权限后的查看接口.png](https://upload-images.jianshu.io/upload_images/16056606-4cbffae541485a16.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

postman能返回接口的信息

#不足
需要跳转才能返回自定义信息
#改进
1.可以把查询到的信息扔进redis,这样可以缓解每次请求接口都要查询数据库的压力,因为是demo所以我就没写出相关代码,但是大家可以自己尝试着去实现看看
2.还有一些零零碎碎写得不是很优雅的代码
...
#推荐
推荐大家下载chrome的一款插件:octotree,具体效果如图下
![插件.png](https://upload-images.jianshu.io/upload_images/16056606-2aa30da070d2e127.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
#源码
[GitHub传送门](https://github.com/LionZzzi/shiro-demo)

