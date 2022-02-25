package ch.noser.uek223ex8.core.security.authentication;

import ch.noser.uek223ex8.core.security.config.JWTProperties;
import ch.noser.uek223ex8.domain.user.User;
import ch.noser.uek223ex8.domain.user.UserDetailsImpl;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.UUID;

public class LoginHandler extends AbstractAuthenticationProcessingFilter {

    private final ObjectMapper objectMapper;
    private final JWTProperties jwtProperties;
    private final AuthenticationService authenticationService;

    public LoginHandler(RequestMatcher requestMatcher, AuthenticationManager authenticationManager, ObjectMapper objectMapper,
                        JWTProperties jwtProperties, AuthenticationService authenticationService) {
        super(requestMatcher);
        this.authenticationService = authenticationService;
        setAuthenticationManager(authenticationManager);
        this.objectMapper = objectMapper;
        this.jwtProperties = jwtProperties;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException {
        LoginDTO login = objectMapper.readValue(request.getInputStream(), LoginDTO.class);

        return getAuthenticationManager()
                .authenticate(new UsernamePasswordAuthenticationToken(login.getEmail(), login.getPassword()));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException {
        User authenticated = ((UserDetailsImpl) authResult.getPrincipal()).getUser();

        UUID authenticatedId = authenticated.getId();

        String token = Jwts.builder()
                .setSubject(authenticatedId.toString())
                .setExpiration(new Date(System.currentTimeMillis() + jwtProperties.getExpirationMillis()))
                .signWith(SignatureAlgorithm.HS512, jwtProperties.getSecret())
                .setIssuer(jwtProperties.getIssuer())
                .compact();

        response.addHeader(jwtProperties.getHeaderName(), jwtProperties.getTokenPrefix() + " " + token);

        // Expose the Headers
        response.addHeader("Access-Control-Expose-Headers", jwtProperties.getHeaderName());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        objectMapper.writeValue(response.getOutputStream(), authenticationService.getAuthenticationResponse(authenticatedId));
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed)
            throws IOException {

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(new ObjectMapper().writeValueAsString(failed.getMessage()));

    }
}
