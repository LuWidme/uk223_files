package ch.noser.uek223ex8.core.security.authentication;

import ch.noser.uek223ex8.domain.user.dto.UserDTO;

import java.util.UUID;

public interface AuthenticationService {

    UserDTO getAuthenticationResponse(UUID userId);

    void authenticate(String authenticationHeader);

}
