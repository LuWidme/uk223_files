package ch.noser.uek223ex8.core.security;

import ch.noser.uek223ex8.core.security.authentication.AuthenticationService;
import ch.noser.uek223ex8.core.security.authentication.LoginHandler;
import ch.noser.uek223ex8.core.security.authorization.AuthorizationFilter;
import ch.noser.uek223ex8.core.security.config.JWTProperties;
import ch.noser.uek223ex8.domain.user.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final JWTProperties jwtProperties;
    private final ObjectMapper objectMapper;
    private final UserService userService;
    private final BCryptPasswordEncoder passwordEncoder;
    private final AuthenticationService authenticationService;

    @Autowired
    public SecurityConfiguration(
            JWTProperties jwtProperties, ObjectMapper objectMapper, UserService userService,
            BCryptPasswordEncoder passwordEncoder, AuthenticationService authenticationService) {
        this.jwtProperties = jwtProperties;
        this.objectMapper = objectMapper;
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.authenticationService = authenticationService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable()
                .authorizeRequests()
                .antMatchers("/v3/api-docs/**", "/webjars/**").permitAll()
                .antMatchers(HttpMethod.POST, "/users", "/users/").permitAll()
                .antMatchers(HttpMethod.POST, "/login", "/login/").permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilterAfter(loginHandler(), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(authorizationFilter(), UsernamePasswordAuthenticationFilter.class)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService).passwordEncoder(passwordEncoder);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("*"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        configuration.setAllowCredentials(true);
        configuration.setAllowedHeaders(List.of("Authorization", "Cache-Control", "Content-Type"));

        UrlBasedCorsConfigurationSource configurationSource = new UrlBasedCorsConfigurationSource();
        configurationSource.registerCorsConfiguration("/**", configuration);

        return configurationSource;
    }

    @Bean
    public LoginHandler loginHandler() throws Exception {
        return new LoginHandler(new AntPathRequestMatcher("/login", "POST"), authenticationManager(), objectMapper, jwtProperties,
            authenticationService);
    }

    @Bean
    public AuthorizationFilter authorizationFilter() {
        return new AuthorizationFilter(authenticationService, jwtProperties);
    }

}
