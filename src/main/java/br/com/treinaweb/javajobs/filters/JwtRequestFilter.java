package br.com.treinaweb.javajobs.filters;

import br.com.treinaweb.javajobs.services.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    private static final String TOKEN_TUPE = "Bearer ";


    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String token = "";
        String username = "";

        String authorizationHeader = request.getHeader("Authorization");

        if (isTokenPresente(authorizationHeader)){
            token = authorizationHeader.substring(TOKEN_TUPE.length());
            username = jwtService.getUsernameFromToken(token);
        }

        if (isUsernameNotInContext(username)){
          addUsernameInContext(request,username, token);
        }

        filterChain.doFilter(request, response);
    }

    private boolean isTokenPresente(String authorzationHeader){
        return authorzationHeader != null && authorzationHeader.startsWith(TOKEN_TUPE);
    }

    private boolean isUsernameNotInContext(String username){
      return  !username.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null;
    }

    private void addUsernameInContext(HttpServletRequest request, String username, String token){
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authentication);

    }
}
