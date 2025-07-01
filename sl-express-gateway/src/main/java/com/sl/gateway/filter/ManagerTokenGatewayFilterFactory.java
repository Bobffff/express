package com.sl.gateway.filter;

import cn.hutool.core.collection.CollUtil;
import com.itheima.auth.factory.AuthTemplateFactory;
import com.itheima.auth.sdk.AuthTemplate;
import com.itheima.auth.sdk.common.Result;
import com.itheima.auth.sdk.dto.AuthUserInfoDTO;
import com.itheima.auth.sdk.service.TokenCheckService;
import com.sl.gateway.config.MyConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.Collection;
import java.util.List;

/**
 * 后台管理员token拦截处理
 */
@Component
public class ManagerTokenGatewayFilterFactory extends AbstractGatewayFilterFactory<Object> implements AuthFilter {

    @Resource
    private MyConfig myConfig;
    @Resource
    private TokenCheckService tokenCheckService;
    // 配置文件中配置的允许放行的角色ID
    @Value("${role.manager}")
    private List<Long> managerRoleIds;

    @Override
    public GatewayFilter apply(Object config) {
        //由于实现了AuthFilter接口，所以可以传递this对象到TokenGatewayFilter中
        return new TokenGatewayFilter(this.myConfig, this);
    }

    @Override
    public AuthUserInfoDTO check(String token) {
        //校验token
        return tokenCheckService.parserToken(token);
    }


    @Override
    public Boolean auth(String token, AuthUserInfoDTO authUserInfoDTO, String path) {
        // 获取authTemplate对象
        AuthTemplate authTemplate = AuthTemplateFactory.get(token);
        //根据登录用户的userID查询用户的角色ID
        Result<List<Long>> roleByUserId = authTemplate.opsForRole().findRoleByUserId(authUserInfoDTO.getUserId());
        List<Long> roleIds = roleByUserId.getData();
        // 和配置文件中的角色ID做并集，存在则放行
        Collection<Long> intersection = CollUtil.intersection(roleIds, managerRoleIds);
        return CollUtil.isNotEmpty(intersection);
    }
}
