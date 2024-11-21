package com.github.mohammedismaiel.auth;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@SpringBootApplication
public class AuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }

    // @Bean
    // UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
    // UserDetails user = User.builder()
    // .username("user")
    // .password(passwordEncoder.encode("user"))
    // .roles("USER")
    // .build();
    // return new InMemoryUserDetailsManager(user);
    // }
}

@Configuration
@EnableWebSecurity
class SecurityConfig {
    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
            UsernamePasswordAuthenticationProvider usernamePasswordAuthProvider,
            OtpAuthenticationProvider otpAuthenticationProvider) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());
        http.exceptionHandling((exceptions) -> exceptions

                .defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(
                                MediaType.TEXT_HTML)))
                .cors(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
            UsernamePasswordAuthenticationProvider usernamePasswordAuthProvider,
            OtpAuthenticationProvider otpAuthenticationProvider) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/error", "/assets/**", "/logout").permitAll()
                        .requestMatchers("/login/**").anonymous()
                        .requestMatchers("/ott", "/verify-ott").hasAnyAuthority("PARTIAL_AUTH_T")
                        .requestMatchers("/otp", "/verify-otp").hasAnyAuthority("PARTIAL_AUTH")
                        .anyRequest().hasAnyAuthority("ROLE_USER"))
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .successHandler((request, response, authentication) -> {
                            response.sendRedirect("/ott");
                        })
                        .failureHandler((request, response, exception) -> {
                            response.sendRedirect("/login?error");
                        }))
                .logout(logout -> logout.logoutUrl("/logout")
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")))
                .authenticationProvider(usernamePasswordAuthProvider)
                .authenticationProvider(otpAuthenticationProvider)
                .csrf(csrf -> csrf.ignoringRequestMatchers("/login", "/logout", "/verify-otp"))
                .cors(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        RegisteredClient front = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("admin-front")
                .clientSecret("{noop}front")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                // .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:5555")
                .postLogoutRedirectUri("http://localhost:5555")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                // .scope("read")
                .clientSettings(
                        ClientSettings.builder().requireProofKey(true).build())
                .build();
        RegisteredClient resource = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("resource")
                .clientSecret(passwordEncoder.encode("resource"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://spring.io")
                .scope(OidcScopes.OPENID)
                .scope("read")
                .build();
        return new InMemoryRegisteredClientRepository(front, resource);
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer() {
        return context -> {
            Authentication authentication = context.getPrincipal();
            context.getClaims()
                    .claim("authority",
                            authentication.getAuthorities().stream().map(authority -> authority.getAuthority())
                                    .collect(Collectors.joining(
                                            ",")));
        };
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:5555"));
        configuration.setAllowedMethods(Arrays.asList("*"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}

@Service
@AllArgsConstructor
class OtpService {
    private final UserRepository userRepository;
    private static final long OTP_VALID_DURATION = 5;

    public String generateOtp(User user) {
        String otp = String.format("%06d", new Random().nextInt(1000000));
        user.setOtp(otp);
        user.setOtpGeneratedTime(LocalDateTime.now());
        userRepository.save(user);
        return otp;
    }

    public boolean validateOtp(String username, String inputOtp) {
        var user = userRepository.findByUsername(username).get();
        if (user == null || user.getOtp() == null)
            return false;
        return user.getOtp().equals(inputOtp);
        // &&
        // LocalDateTime.now().isBefore(user.getOtpGeneratedTime().plusMinutes(OTP_VALID_DURATION));
    }
}

@Component
@AllArgsConstructor
class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {
    private UserDetailsService userDetailsService;
    private OtpService otpService;
    private PasswordEncoder passwordEncoder;
    private UserRepository userRepository;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        UserDetails user = userDetailsService.loadUserByUsername(username);
        if (user != null && passwordEncoder.matches(password, user.getPassword())) {
            otpService.generateOtp(userRepository.findByUsername(username).get());
            return new UsernamePasswordAuthenticationToken(
                    username,
                    password,
                    Collections.singleton(new SimpleGrantedAuthority("PARTIAL_AUTH_T")));
        }
        throw new BadCredentialsException("Invalid credentials");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

@Component
@AllArgsConstructor
class OtpAuthenticationProvider implements AuthenticationProvider {
    private OtpService otpService;
    private UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String otp = authentication.getCredentials().toString();
        System.out.println("OTP Authentication attempt for user: " + username);
        if (otpService.validateOtp(username, otp)) {
            UserDetails user = userDetailsService.loadUserByUsername(username);
            // Create a new authentication with the FULL user authorities
            Authentication fullAuth = new UsernamePasswordAuthenticationToken(
                    user, // Use the full UserDetails object as principal
                    null, // credentials can be null after authentication
                    user.getAuthorities() // Use the original user authorities (ROLE_USER, etc.)
            );
            System.out.println("OTP Validation successful. New authorities: " + fullAuth.getAuthorities());
            return fullAuth;
        }
        System.out.println("OTP Validation failed");
        throw new BadCredentialsException("Invalid OTP");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

@Component
@AllArgsConstructor
class OttAuthenticationProvider implements AuthenticationProvider {
    private UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String otp = authentication.getCredentials().toString();
        System.out.println("OTP Authentication attempt for user: " + username);
        if (otp.equals("123")) {
            UserDetails user = userDetailsService.loadUserByUsername(username);
            // Create a new authentication with the FULL user authorities
            Authentication fullAuth = new UsernamePasswordAuthenticationToken(
                    user, // Use the full UserDetails object as principal
                    null, // credentials can be null after authentication
                    List.of(new SimpleGrantedAuthority("PARTIAL_AUTH")) // Use the original user authorities
                                                                        // (ROLE_USER, etc.)
            );
            System.out.println("OTP Validation successful. New authorities: " + fullAuth.getAuthorities());
            return fullAuth;
        }
        System.out.println("OTP Validation failed");
        throw new BadCredentialsException("Invalid OTT");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

@RestController
class DemoController {
    @GetMapping("/test")
    String hello() {
        return "Hello from protected resource!";
    }

    @GetMapping("/")
    String helloo() {
        return "Hello!";
    }
}

@Controller
@AllArgsConstructor
class AuthController {
    private OtpAuthenticationProvider otpAuthenticationProvider;
    private OttAuthenticationProvider ottAuthenticationProvider;
    private final HttpSessionRequestCache requestCache = new HttpSessionRequestCache();

    @GetMapping("/login")
    public String loginPage() {
        return "login"; // returns login.html
    }

    @GetMapping("/otp")
    public String otpPage(Authentication authentication) {
        // Check if user has completed first factor
        if (authentication == null ||
                !authentication.getAuthorities().contains(new SimpleGrantedAuthority("PARTIAL_AUTH"))) {
            return "redirect:/login";
        }
        return "otp";
    }

    @GetMapping("/ott")
    public String ottPage(Authentication authentication) {
        // Check if user has completed first factor
        if (authentication == null ||
                !authentication.getAuthorities().contains(new SimpleGrantedAuthority("PARTIAL_AUTH_T"))) {
            return "redirect:/login";
        }
        return "ott";
    }

    @PostMapping("/verify-otp")
    public String verifyOtp(@RequestParam String otp, HttpSession session, HttpServletRequest request,
            HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        try {
            Authentication verified = otpAuthenticationProvider.authenticate(
                    new UsernamePasswordAuthenticationToken(username, otp));
            SecurityContextHolder.getContext().setAuthentication(verified);
            // Retrieve the saved request
            SavedRequest savedRequest = requestCache.getRequest(request, response);
            if (savedRequest != null) {
                // Redirect to the original URL
                return "redirect:" + savedRequest.getRedirectUrl();
            }
            return "redirect:/";
        } catch (AuthenticationException e) {
            return "redirect:/otp?error";
        }
    }

    @PostMapping("/verify-ott")
    public String verifyOtt(@RequestParam String otp, HttpSession session, HttpServletRequest request,
            HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        try {
            Authentication verified = ottAuthenticationProvider.authenticate(
                    new UsernamePasswordAuthenticationToken(username, otp));
            SecurityContextHolder.getContext().setAuthentication(verified);
            // Retrieve the saved request
            // SavedRequest savedRequest = requestCache.getRequest(request, response);
            // if (savedRequest != null) {
            // // Redirect to the original URL
            // return "redirect:" + savedRequest.getRedirectUrl();
            // }
            return "redirect:/otp";
        } catch (AuthenticationException e) {
            return "redirect:/ott?error";
        }
    }
}

@AllArgsConstructor
@Component
class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}

@Data
@NoArgsConstructor
@Entity
@Table(name = "users")
class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column
    private String otp;

    @Column
    private LocalDateTime otpGeneratedTime;

    @Column(nullable = false)
    private String role = "ROLE_USER";

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role));
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
