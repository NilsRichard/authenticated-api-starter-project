package fr.nrich.model.auth.dto;

import java.io.Serializable;
import java.util.List;

/**
 * Classic response for a JWT authenticated request
 * 
 * @author Nils Richard
 *
 */
public class JwtAuthenticationResponse implements Serializable {
    private static final long serialVersionUID = 6098474392852070760L;
    
    private String token;
    private String refreshToken;
    private Long expiresIn;
    private List<String> authorities;

    /**
     * Important for JSON serialization
     */
    public JwtAuthenticationResponse() {
    }
    
    public JwtAuthenticationResponse(String token, String refreshToken, Long expiresIn,
            List<String> authorities) {
        super();
        this.token = token;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.authorities = authorities;
    }

    public List<String> getAuthorities() {
        return authorities;
    }

    public String getToken() {
        return token;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public Long getExpiresIn() {
        return expiresIn;
    }

}