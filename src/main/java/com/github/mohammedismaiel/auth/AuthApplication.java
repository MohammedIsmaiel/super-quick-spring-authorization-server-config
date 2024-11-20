package com.github.mohammedismaiel.auth;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
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
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
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

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.AllArgsConstructor;

@SpringBootApplication
public class AuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }

    @Bean
    UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder.encode("user"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
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
                        .requestMatchers("/error", "/assets/**").permitAll()
                        .requestMatchers("/login").anonymous()
                        .requestMatchers("/otp", "/verify-otp").hasAnyAuthority("PARTIAL_AUTH")
                        .anyRequest().authenticated())
                .requestCache(requestCache -> requestCache
                        .requestCache(new HttpSessionRequestCache() {
                            @Override
                            public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
                                String requestUrl = request.getRequestURL().toString();
                                request.getSession().setAttribute("originalRequestUrl", requestUrl);
                                super.saveRequest(request, response);
                            }
                        }))
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .successHandler((request, response, authentication) -> {
                            String redirectUrl = (String) request.getSession().getAttribute("originalRequestUrl");
                            if (redirectUrl != null) {
                                request.getSession().removeAttribute("originalRequestUrl");
                            }
                            response.sendRedirect("/otp");
                        })
                        .failureHandler((request, response, authentication) -> {
                            String redirectUrl = (String) request.getSession().getAttribute("originalRequestUrl");
                            if (redirectUrl != null) {
                                request.getSession().removeAttribute("originalRequestUrl");
                            }
                            response.sendRedirect("/otp");
                        })
                        .failureHandler((request, response, exception) -> {
                            response.sendRedirect("/login?error");
                        }))
                .authenticationProvider(usernamePasswordAuthProvider)
                .authenticationProvider(otpAuthenticationProvider)
                .csrf(csrf -> csrf.ignoringRequestMatchers("/login", "/verify-otp"))
                .cors(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    RegisteredClientRepository registeredClientRepository() {
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
                .clientSecret("{noop}resource")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:5555/auth")
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
class OtpService {
    private final Map<String, String> otpStore = new ConcurrentHashMap<>();

    public String generateOtp(String username) {
        String otp = String.format("%06d", new Random().nextInt(1000000));
        otpStore.put(username, otp);
        System.out.println("Generated OTP for " + username + ": " + otp); // For demo purposes
        return otp;
    }

    public boolean validateOtp(String username, String otp) {
        String storedOtp = otpStore.get(username);
        if (storedOtp != null && storedOtp.equals(otp)) {
            otpStore.remove(username); // One-time use
            return true;
        }
        return false;
    }
}

@Component
@AllArgsConstructor
class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {
    private UserDetailsService userDetailsService;
    private OtpService otpService;
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        UserDetails user = userDetailsService.loadUserByUsername(username);
        if (user != null && passwordEncoder.matches(password, user.getPassword())) {
            otpService.generateOtp(username);
            return new UsernamePasswordAuthenticationToken(
                    username,
                    password,
                    Collections.singleton(new SimpleGrantedAuthority("PARTIAL_AUTH")));
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

    @PostMapping("/verify-otp")
    public String verifyOtp(@RequestParam String otp, HttpSession session) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        try {
            Authentication verified = otpAuthenticationProvider.authenticate(
                    new UsernamePasswordAuthenticationToken(username, otp));
            SecurityContextHolder.getContext().setAuthentication(verified);
            return "redirect:/oauth2/authorize";
        } catch (AuthenticationException e) {
            return "redirect:/otp?error";
        }
    }
}