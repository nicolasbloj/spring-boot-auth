package com.auth0.samples.authapi.security;

import static com.auth0.samples.authapi.security.SecurityConstants.SIGN_UP_URL;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {
  private UserDetailsService userDetailsService;
  private BCryptPasswordEncoder bCryptPasswordEncoder;

  public WebSecurity(UserDetailsService userDetailsService,
      BCryptPasswordEncoder bCryptPasswordEncoder) {
    this.userDetailsService = userDetailsService;
    this.bCryptPasswordEncoder = bCryptPasswordEncoder;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.cors().and().csrf().disable().authorizeRequests().antMatchers(HttpMethod.POST, SIGN_UP_URL)
        .permitAll().anyRequest().authenticated().and()
        .addFilter(new JWTAuthenticationFilter(authenticationManager()))
        .addFilter(new JWTAuthorizationFilter(authenticationManager()));
  }

  @Override
  public void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
  }

  @Bean
  CorsConfigurationSource corsConfigurationSource() {
    final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
    return source;
  }
}

/*
 * configure(HttpSecurity http): a method where we can define which resources are public and which
 * are secured. In our case, we set the SIGN_UP_URL endpoint as being public and everything else as
 * being secured. We also configure CORS (Cross-Origin Resource Sharing) support through http.cors()
 * and we add a custom security filter in the Spring Security filter chain.
 * configure(AuthenticationManagerBuilder auth): a method where we defined a custom implementation
 * of UserDetailsService to load user-specific data in the security framework. We have also used
 * this method to set the encrypt method used by our application (BCryptPasswordEncoder).
 */

