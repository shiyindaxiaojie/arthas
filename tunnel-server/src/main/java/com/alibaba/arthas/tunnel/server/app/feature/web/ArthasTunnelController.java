package com.alibaba.arthas.tunnel.server.app.feature.web;

import com.alibaba.arthas.tunnel.server.AgentInfo;
import com.alibaba.arthas.tunnel.server.TunnelServer;
import com.alibaba.arthas.tunnel.server.app.feature.dto.ArthasAgent;
import com.alibaba.arthas.tunnel.server.app.feature.dto.ArthasAgentGroup;
import com.google.common.base.Strings;
import com.google.common.collect.Sets;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Arthas 接口
 *
 * @author <a href="mailto:shiyindaxiaojie@gmail.com">gyl</a>
 * @since 1.0.0
 */
@RequiredArgsConstructor
@Slf4j
@RestController
public class ArthasTunnelController {

    public static final String AGENT_SPLIT = "@";

    private static final String ROLE_PREFIX = "ROLE_";

    private final TunnelServer tunnelServer;

    private final UserDetailsService userDetailsService;

    @GetMapping(value = "/api/arthas/agents")
    public List<ArthasAgentGroup> getAgents(Principal principal) {
        Set<String> roles = getCurrentUserRole(principal.getName());
        if (roles.isEmpty()) {
            return Collections.emptyList();
        }

        boolean isSuperUser = isSuperAdmin(roles);

        Map<String, AgentInfo> agentInfoMap = tunnelServer.getAgentInfoMap();
        Map<String, List<ArthasAgent>> map = new HashMap<>(16);
        agentInfoMap.forEach((k, v) -> {
            String[] split = k.split(AGENT_SPLIT, 2);
            String appName = split[0];
            if (split.length > 1) {
                if (isSuperUser || accessApp(roles, appName)) {
                    List<ArthasAgent> agents = map.computeIfAbsent(appName, k1 -> new ArrayList<>());
                    ArthasAgent agent = new ArthasAgent();
                    agent.setId(split[1]);
                    agent.setInfo(v);
                    agents.add(agent);
                }
            } else {
                log.warn("Ignore app `{}` due to might not set agent id", appName);
            }
        });
        List<ArthasAgentGroup> groups = new ArrayList<>();
        map.forEach((k, v) -> {
            ArthasAgentGroup group = new ArthasAgentGroup();
            group.setAgents(v);
            group.setService(k);
            groups.add(group);
        });
        return groups;
    }

    private Set<String> getCurrentUserRole(String userName) {
        if (Strings.isNullOrEmpty(userName)) {
            return Collections.emptySet();
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(userName);
        if (userDetails == null) {
            return Collections.emptySet();
        }
        return userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .filter(Objects::nonNull).collect(Collectors.toSet());
    }

    private boolean isSuperAdmin(Set<String> roles) {
        return accessApp(roles, "ADMIN");
    }

    private boolean accessApp(Set<String> roles, String appName) {
        for (String role : roles) {
            String pattern = role.replace("*", ".*");

            if (!pattern.startsWith("^")) {
                pattern = "^" + pattern;
            }
            if (!pattern.endsWith("$")) {
                pattern += "$";
            }

            Pattern r = Pattern.compile(pattern);
            if (r.matcher(ROLE_PREFIX + appName).matches()) {
                return true;
            }
        }
        return false;
    }

    public static void main(String[] args) {
        ArthasTunnelController controller = new ArthasTunnelController(null,null);
        Set<String> roles = Sets.newHashSet("bizcollege-*");
        System.out.println(controller.accessApp(roles, "bizcollege-uaa"));
        System.out.println(controller.accessApp(roles, "bizcollege-order"));
        System.out.println(controller.accessApp(roles, "fois-openapi"));
        System.out.println(controller.accessApp(roles, "puyiwm-uaa"));
    }
}
