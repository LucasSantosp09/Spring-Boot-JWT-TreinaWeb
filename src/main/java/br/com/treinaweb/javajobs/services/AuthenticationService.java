package br.com.treinaweb.javajobs.services;

import br.com.treinaweb.javajobs.auth.AuthenticateUser;
import br.com.treinaweb.javajobs.dto.JwtResponse;
import br.com.treinaweb.javajobs.dto.UserDTO;
import br.com.treinaweb.javajobs.models.User;
import br.com.treinaweb.javajobs.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class AuthenticationService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User foundUser = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(
                        String.format("Usuário %s não encontrado", username)
                ));
        return new AuthenticateUser(foundUser);
    }

    public JwtResponse createJwtResponse(UserDTO userDTO) {
        String username = userDTO.getUsername();
        String password = userDTO.getPassword();

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, password);

        Authentication authenticateUser = authenticationManager.authenticate(authentication);

        return createJwtResponse(authenticateUser);

    }

    public JwtResponse createJwtResponse(String refreshToken) {
        String username = jwtService.getUsernameFromToken(refreshToken);

        String password = loadUserByUsername(username).getPassword();

        Authentication authenticatedUser = new UsernamePasswordAuthenticationToken(username, password);

        return createJwtResponse(authenticatedUser);

    }

    private JwtResponse createJwtResponse(Authentication authentication){
        String token = jwtService.generateToken(authentication);

        Date expiresAt = jwtService.getExpirationFromToken(token);

        String refreshToken = jwtService.generateRefreshToken(authentication.getName());

        return new JwtResponse(token, "Bearer", expiresAt, refreshToken);
    }
}
