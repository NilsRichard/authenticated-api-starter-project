package fr.nrich.model.auth.dto;

import java.io.Serializable;
/**
 * Model for a refresh request from client
 * 
 * @author Nils Richard
 *
 */
public class JwtRefreshResponse implements Serializable {
    private static final long serialVersionUID = -7724494183255621013L;
    private final String jwttoken;

    public JwtRefreshResponse(String jwttoken) {
        this.jwttoken = jwttoken;
    }

    public String getToken() {
        return this.jwttoken;
    }

}
