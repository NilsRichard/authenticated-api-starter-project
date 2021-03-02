package fr.nrich.config.filters;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import fr.nrich.config.WebSecurityConfig;
import fr.nrich.service.JwtUserDetailsService;
import fr.nrich.utils.JwtTokenUtil;
import fr.nrich.utils.errors.InvalidAuthorizationHeaderException;
import fr.nrich.utils.errors.InvalidJwtTokenException;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

/**
 * This configuration adds a filter on all requests to validate the JWT access
 * token before accessing the API entry points
 * 
 * @author Nils Richard
 *
 */
@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    Logger logger = LogManager.getLogger(getClass());

    @Autowired
    private JwtUserDetailsService jwtUserDetailsService;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        // Don't filter on /auth/*
        boolean filter = true;
        for (String whiteListedUrl : WebSecurityConfig.WHITE_LIST) {
            if (request.getRequestURI().matches(whiteListedUrl.replace("*", ".*"))) {
                filter = false;
                chain.doFilter(request, response);
            }
        }
        if (filter) {

            // Check authorization header
            final String requestTokenHeader = request.getHeader("Authorization");
            if (requestTokenHeader == null || !requestTokenHeader.startsWith("Bearer "))
                throw new InvalidAuthorizationHeaderException();

            String username = null;
            String jwtToken = requestTokenHeader.substring(7);
            try {
                username = jwtTokenUtil.getUsernameFromToken(jwtToken);
            } catch (IllegalArgumentException e) {
                throw new InvalidJwtTokenException("Unable to get JWT Token");
            } catch (ExpiredJwtException e) {
                throw new InvalidJwtTokenException("JWT Token has expired");
            } catch (MalformedJwtException e) {
                throw new InvalidJwtTokenException("JWT token malformed");
            } catch (UnsupportedJwtException e) {
                throw new InvalidJwtTokenException("JWT Token is unsupported");
            } catch (SignatureException e) {
                throw new InvalidJwtTokenException("JWT token signature can't be trusted");
            }

            // Once we get the token validate it.
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = null;
                try {
                    userDetails = this.jwtUserDetailsService.loadUserByUsername(username);
                } catch (UsernameNotFoundException e) {
                    logger.debug("User not found");
                }

                if (userDetails != null) {
                    if (!jwtTokenUtil.validateToken(jwtToken, userDetails))
                        throw new InvalidJwtTokenException("JWT token is a refresh token");

                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    usernamePasswordAuthenticationToken
                            .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    // After setting the Authentication in the context, we specify
                    // that the current user is authenticated. So it passes the
                    // Spring Security Configurations successfully.
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                }
            }
            chain.doFilter(request, response);
        }
    }
}
