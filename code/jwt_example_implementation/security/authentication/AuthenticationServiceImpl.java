package ch.noser.uek223ex8.core.security.authentication;

import ch.noser.uek223ex8.core.security.config.JWTProperties;
import ch.noser.uek223ex8.domain.user.User;
import ch.noser.uek223ex8.domain.user.UserDetailsImpl;
import ch.noser.uek223ex8.domain.user.UserService;
import ch.noser.uek223ex8.domain.user.dto.UserDTO;
import ch.noser.uek223ex8.domain.user.dto.UserMapper;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.HttpClientErrorException;

import java.util.NoSuchElementException;
import java.util.UUID;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserService userService;
    private final UserMapper userMapper;
    private final JWTProperties jwtProperties;

    public AuthenticationServiceImpl(
            UserService userService,
            UserMapper userMapper, JWTProperties jwtProperties
    ) {
        this.userService = userService;
        this.userMapper = userMapper;
        this.jwtProperties = jwtProperties;
    }

    @Override
    @Transactional
    public UserDTO getAuthenticationResponse(UUID userId) {

        User user = userService.findById(userId);

        return userMapper.toDTO(user);
    }

    @Override
    public void authenticate(String authToken) {
        if (authToken != null) {
            SecurityContextHolder.getContext().setAuthentication(getAuthentication(authToken));
        }
    }

    private Authentication getAuthentication(String authToken) {
        if (authToken.startsWith(jwtProperties.getTokenPrefix())) {
            try {
                UUID userId = UUID.fromString(parseSubject(authToken));

                UserDetails userDetails = new UserDetailsImpl(userService.findById(userId));

                return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            } catch (JwtException | NoSuchElementException exception) {
                System.err.println(exception.getMessage());
            }
        }

        throw new HttpClientErrorException(HttpStatus.FORBIDDEN);
    }

    private String parseSubject(String header) throws JwtException {
        return Jwts.parser()
                .setSigningKey(jwtProperties.getSecret())
                .parseClaimsJws(header.replace(jwtProperties.getTokenPrefix() + " ", ""))
                .getBody()
                .getSubject();
    }
}
