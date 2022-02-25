package ch.noser.uek223ex8.core.security.authorization;

import ch.noser.uek223ex8.core.security.authentication.AuthenticationService;
import ch.noser.uek223ex8.core.security.config.JWTProperties;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthorizationFilter extends OncePerRequestFilter {

    private final AuthenticationService authenticationService;
    private final JWTProperties jwtProperties;

    public AuthorizationFilter(AuthenticationService authenticationService, JWTProperties jwtProperties) {
        this.authenticationService = authenticationService;
        this.jwtProperties = jwtProperties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
        String authToken = request.getHeader(jwtProperties.getHeaderName());

        authenticationService.authenticate(authToken);

        filterChain.doFilter(request, response);
    }

}
