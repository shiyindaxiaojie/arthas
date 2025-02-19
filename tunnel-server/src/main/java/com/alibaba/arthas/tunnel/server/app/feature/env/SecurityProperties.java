package com.alibaba.arthas.tunnel.server.app.feature.env;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Set;

/**
 * Arthas 自定义授权配置
 *
 * @author <a href="mailto:shiyindaxiaojie@gmail.com">gyl</a>
 * @since 3.6.6
 */
@Data
@ConfigurationProperties(prefix = SecurityProperties.PREFIX)
public class SecurityProperties {

    public static final String PREFIX = "spring.security";

    private Set<org.springframework.boot.autoconfigure.security.SecurityProperties.User> users;
}
