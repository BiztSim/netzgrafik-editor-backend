package ch.sbb.pfi.netzgrafikeditor.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@EnableWebSecurity
@Configuration
public class SecurityConfig {
    private static final String ROLE_PREFIX = "ROLE_";

    public static final String USER_ROLE = "ROLE_User";
    public static final String ADMIN_ROLE = "ROLE_Admin";
    public static final String NGE_USER_ROLE = "ROLE_nge_user";
    public static final String NGE_ADMIN_ROLE = "ROLE_nge_admin";

    @Value("${auth.roles-claim-name:roles}")
    private String rolesClaimName;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors(withDefaults())
                .sessionManagement(
                        sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(
                        authorizeRequests ->
                                authorizeRequests
                                        .requestMatchers(HttpMethod.GET, "/actuator/health")
                                        .permitAll()
                                        .requestMatchers(
                                                "/",
                                                "/v3/api-docs/**",
                                                "/swagger-ui/**",
                                                "/swagger-ui.html")
                                        .permitAll()
                                        .anyRequest()
                                        .hasAnyAuthority(USER_ROLE, ADMIN_ROLE, NGE_USER_ROLE, NGE_ADMIN_ROLE))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
            List<String> authorities = new ArrayList<>();
            Object rolesObj = jwt.getClaims().get(rolesClaimName);
            if (rolesObj == null && !"roles".equals(rolesClaimName)) {
                rolesObj = jwt.getClaims().get("roles");
            }
            if (rolesObj == null) {
                rolesObj = jwt.getClaims().get("groups");
            }
            if (rolesObj instanceof Collection<?> col) {
                col.forEach(r -> {
                    String roleName = r.toString();
                    authorities.add(ROLE_PREFIX + roleName);
                    // Map LLDAP nge_ groups to standard roles
                    if ("nge_user".equalsIgnoreCase(roleName)) {
                        authorities.add(USER_ROLE);
                    } else if ("nge_admin".equalsIgnoreCase(roleName)) {
                        authorities.add(ADMIN_ROLE);
                        authorities.add(USER_ROLE);
                    }
                });
            }
            return authorities.stream()
                    .distinct()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        });
        return jwtAuthenticationConverter;
    }
}
