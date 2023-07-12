package br.com.treinaweb.javajobs.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtResponse {
    private String token;

    private String type;

    private Date expiresAt;

    private String refreshToken;
}
