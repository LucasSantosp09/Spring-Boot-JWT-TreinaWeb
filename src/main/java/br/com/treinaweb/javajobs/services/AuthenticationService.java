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

        String token = jwtService.generateToken(authenticateUser);

        Date expiresAt = jwtService.getExpirationFromToken(token);

        return new JwtResponse(token, "Bearer", expiresAt);

    }
}
