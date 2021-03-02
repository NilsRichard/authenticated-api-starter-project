package fr.nrich.controller;

import java.util.List;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import fr.nrich.model.auth.dto.JwtAuthenticationRequest;
import fr.nrich.model.auth.dto.JwtAuthenticationResponse;
import fr.nrich.model.auth.dto.JwtRefreshRequest;
import fr.nrich.model.auth.dto.JwtRefreshResponse;
import fr.nrich.model.auth.dto.JwtRegisterRequest;
import fr.nrich.service.JwtUserDetailsService;
import fr.nrich.service.RefreshTokenService;
import fr.nrich.utils.JwtTokenUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import javassist.tools.web.BadHttpRequest;

/**
 * Defines the authentication entry points, there is an exception in
 * configuration to allow unauthenticated requests to theses entry points
 * 
 * @author Nils Richard
 *
 */
@RestController
@CrossOrigin
@RequestMapping(value = "/auth")
public class JwtAuthenticationController {

    Logger logger = LogManager.getLogger(getClass());

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private JwtUserDetailsService userDetailsService;
    @Autowired
    private RefreshTokenService refreshTokenService;

    /**
     * Entry point to authenticate,
     * 
     * @param authenticationRequest
     * @return
     * @throws Exception
     */
    @Operation(summary = "Authenticate and get an access token")
    @ApiResponses(value = { @ApiResponse(responseCode = "200", description = "Your access token"),
            @ApiResponse(responseCode = "401", description = "If your credentials are incorrect") })
    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<JwtAuthenticationResponse> createAuthenticationToken(
            @RequestBody JwtAuthenticationRequest authenticationRequest) throws Exception {
        authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());

        final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());

        final String token = jwtTokenUtil.generateToken(userDetails);
        final String refreshToken = jwtTokenUtil.generateRefreshToken(userDetails);

        final Long expiresIn = jwtTokenUtil.getAccessTokenExpirationTime();

        refreshTokenService.saveRefreshToken(refreshToken);

        List<String> authorities = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtAuthenticationResponse(token, refreshToken, expiresIn, authorities));
    }

    private void authenticate(String username, String password) throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            logger.debug("User disabled");
            throw new DisabledException("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            logger.debug("Bad credentials");
            throw new BadCredentialsException("INVALID_CREDENTIALS", e);
        } catch (Exception e) {
            logger.debug("Something went wrong", e);
            throw new AccessDeniedException("SOMETHING_WENT_WRONG", e);
        }
    }

    /**
     * Entry point to register, tries to create new account using a unique username
     * and password. Succeed if username has not been used before.
     * 
     * @param authenticationRequest represents specified username and password
     * @throws Exception
     */
    @Operation(summary = "Register to the API")
    @ApiResponses(value = { @ApiResponse(responseCode = "201", description = "User created"),
            @ApiResponse(responseCode = "401", description = "If not admin") })
    @RequestMapping(value = "/register", method = RequestMethod.POST)
    public ResponseEntity<String> register(@RequestBody JwtRegisterRequest newUser) throws Exception {
        if (newUser == null || newUser.getUsername() == null || newUser.getPassword() == null)
            throw new BadHttpRequest();

        userDetailsService.save(newUser.getUsername(), newUser.getPassword(), newUser.getAuthorities());

        return ResponseEntity.status(HttpStatus.CREATED).body("User successfully created");
    }

    /**
     * If given refresh token is valid, returns a new access token
     * 
     * @param refreshRequest
     * @throws Exception
     */
    @Operation(summary = "Refresh an access token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Your access token", content = @Content(schema = @Schema(implementation = JwtRefreshResponse.class))),
            @ApiResponse(responseCode = "401", description = "If refresh token is invalid") })
    @RequestMapping(value = "/token", method = RequestMethod.POST)
    public ResponseEntity<?> refreshAccess(@RequestBody JwtRefreshRequest refreshRequest) throws Exception {
        if (refreshTokenService.isValid(refreshRequest.getRefreshToken())) {
            final String username = jwtTokenUtil.getUsernameFromToken(refreshRequest.getRefreshToken());
            final UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            final String token = jwtTokenUtil.generateToken(userDetails);

            refreshTokenService.refreshValidity(refreshRequest.getRefreshToken());

            return ResponseEntity.ok(new JwtRefreshResponse(token));
        } else {
            throw new BadCredentialsException("INVALID_REFRESH_TOKEN");
        }

    }

    /**
     * Invalidates the given refresh token
     * 
     * @param refreshRequest
     */
    @Operation(summary = "Invalidate a refresh token (logout)")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Refresh token has been invalidated (user is logged out)") })
    @RequestMapping(value = "/token", method = RequestMethod.PUT)
    public ResponseEntity<?> invalidateRefreshToken(@RequestBody JwtRefreshRequest refreshRequest) {
        refreshTokenService.invalidate(refreshRequest.getRefreshToken());
        return ResponseEntity.noContent().build();
    }

}