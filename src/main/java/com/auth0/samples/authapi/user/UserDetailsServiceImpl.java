package com.auth0.samples.authapi.user;


import static java.util.Collections.emptyList;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
  private ApplicationUserRepository applicationUserRepository;

  public UserDetailsServiceImpl(ApplicationUserRepository applicationUserRepository) {
    this.applicationUserRepository = applicationUserRepository;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    ApplicationUser applicationUser = applicationUserRepository.findByUsername(username);
    if (applicationUser == null) {
      throw new UsernameNotFoundException(username);
    }
    return new User(applicationUser.getUsername(), applicationUser.getPassword(), emptyList());
  }
}

/*
 * The only method that we had to implement is loadUserByUsername. When a user tries to
 * authenticate, this method receives the username, searches the database for a record containing
 * it, and (if found) returns an instance of User. The properties of this instance (username and
 * password) are then checked against the credentials passed by the user in the login request. This
 * last process is executed outside this class, by the Spring Security framework.
 */
