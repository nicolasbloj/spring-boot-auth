# spring-boot-auth
Handle authentication and authorization on RESTful APIs written with Spring Boot

https://auth0.com/blog/implementing-jwt-authentication-on-spring-boot/

*Securing RESTful APIs with JWTs

During the authentication process, when a user successfully logs in using their credentials, a JSON Web Token is returned and must be saved locally (typically in local storage).
Whenever the user wants to access a protected route or resource (an endpoint), the user agent must send the JWT, usually in the Authorization header using the Bearer schema, along with the request.
When a backend server receives a request with a JWT, the first thing to do is to validate the token. This consists of a series of steps, and if any of these fails then, the request must be rejected. The following list shows the validation steps needed:

Check that the JWT is well formed
Check the signature
Validate the standard claims
Check the Client permissions (scopes)

			The OAuth 2.0 Authorization Framework: Bearer Token Usage
			http://self-issued.info/docs/draft-ietf-oauth-v2-bearer.html

...

User Authentication and Authorization on Spring Boot


To support both authentication and authorization in our application, we are going to:

-implement an authentication filter to issue JWTS to users sending credentials,
-implement an authorization filter to validate requests containing JWTS,
-create a custom implementation of UserDetailsService
to help Spring Security loading user-specific data in the framework,
-and extend the WebSecurityConfigurerAdapter class to customize 
the security framework to our needs

--The Authentication Filter	
	JWTAuthenticationFilter --> extends UsernamePasswordAuthenticationFilter 
	
Our custom authentication filter overwrites two methods of the base class:

attemptAuthentication: where we parse the user's credentials and issue them to the AuthenticationManager.
successfulAuthentication: which is the method called when a user successfully logs in. We use this method to generate a JWT for this user	
	
--The Authorization Filter
	JWTAuthoriazationFiler --> extends  BasicAuthenticationFilter
	
The most important part of the filter that we've implemented is the private getAuthentication method. This method reads the JWT from the Authorization header, and then uses Jwts to validate the token


---> WebSecurity --> WebSecurityConfigurerAdapter

configure(HttpSecurity http): a method where we can define which resources are public and which are secured. In our case, we set the SIGN_UP_URL endpoint as being public and everything else as being secured. We also configure CORS (Cross-Origin Resource Sharing) support through http.cors() and we add a custom security filter in the Spring Security filter chain.
configure(AuthenticationManagerBuilder auth): a method where we defined a custom implementation of UserDetailsService to load user-specific data in the security framework. We have also used this method to set the encrypt method used by our application (BCryptPasswordEncoder).
corsConfigurationSource(): a method where we can allow/restrict our CORS support. In our case we left it wide open by permitting requests from any source (/**).


Spring Security doesn't come with a concrete implementation of UserDetailsService



The only method that we had to implement is loadUserByUsername. When a user tries to authenticate, this method receives the username, searches the database for a record containing it, and (if found) returns an instance of User. The properties of this instance (username and password) are then checked against the credentials passed by the user in the login request. This last process is executed outside this class, by the Spring Security framework.



TEST


CURL - POSTMAN
