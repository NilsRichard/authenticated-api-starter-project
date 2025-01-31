package fr.nrich.service;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import fr.nrich.dao.APIConsumerDAO;
import fr.nrich.model.auth.APIConsumer;
import fr.nrich.utils.errors.UserAlreadyExistsException;

/**
 * The Spring Security Authentication Manager calls this method for getting the
 * user details from the database when authenticating the user details provided
 * by the user. It overrides the loadUserByUsername for fetching user details
 * from the database using the username.
 * 
 * @author Nils Richard, Maxime Beucher
 *
 */
@Service
public class JwtUserDetailsService implements UserDetailsService {
    Logger logger = LogManager.getLogger(getClass());

    @Autowired
    private APIConsumerDAO apiConsumerDao;

    @Autowired
    private PasswordEncoder bcryptEncoder;

    public void save(String username, String password, List<String> authorities) throws UserAlreadyExistsException {
        if (apiConsumerDao.checkForExistanceUsername(username)) {
            throw new UserAlreadyExistsException("USER_ALREADY_EXISTS");
        }

        APIConsumer newUser = new APIConsumer();
        newUser.setUsername(username);
        newUser.setPassword(bcryptEncoder.encode(password));
        newUser.setAuthorities(authorities);
        apiConsumerDao.save(newUser);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (apiConsumerDao.checkForExistanceUsername(username)) {
            APIConsumer modelUser = apiConsumerDao.getUserByName(username);

            Collection<GrantedAuthority> grantedAuthorities = new HashSet<>();
            for (String auth : modelUser.getAuthorities()) {
                grantedAuthorities.add(new SimpleGrantedAuthority(auth));
            }

            // chiffrer le mot de passe?
            return new User(modelUser.getUsername(), modelUser.getPassword(), grantedAuthorities);
        } else {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }

    }

}
