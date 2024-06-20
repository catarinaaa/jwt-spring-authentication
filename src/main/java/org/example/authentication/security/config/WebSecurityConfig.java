package org.example.authentication.security.config;

import org.example.authentication.appuser.AppUserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;


@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    private final AppUserService appUserService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Value("${config.loginUrl}")
    private String loginUrl;

    @Value("${config.secret}")
    private String secret;

    @Value("${config.accessTokenExpirationTime}")
    private Long accessTokenExpirationTime;

    @Value("${config.resetTokenExpirationTime}")
    private Long resetTokenExpirationTime;

    @Value("${config.origin}")
    private String origin;


    private final String[] AUTH_WHITELIST = {
            "/api/v*/registration/**",
            "/error",
            "/api/v*/token/refresh/**",
            "/oauth2/authorization/github",
            "/login/oauth2/code/**"
    };

    public WebSecurityConfig(AppUserService appUserService, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.appUserService = appUserService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        CustomAuthenticationFilter authenticationFilter = new CustomAuthenticationFilter(providerManager(), secret, accessTokenExpirationTime, resetTokenExpirationTime);
        // Sets login url
        authenticationFilter.setFilterProcessesUrl(loginUrl);
        // Sets custom handler of authentication exceptions to deal without not verified user or wrong password
        authenticationFilter.setAuthenticationFailureHandler(authenticationFailureHandler());

        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests((authorize) -> authorize
                .requestMatchers(AUTH_WHITELIST).permitAll()
                .requestMatchers(loginUrl).permitAll()
                .requestMatchers("/api/v*/admin/**").hasAuthority("ADMIN")
                .requestMatchers("/api/v*/users/").hasAuthority("ADMIN")
                .requestMatchers("/api/v*/users/me").hasAuthority("USER")
                .anyRequest().authenticated())
            .logout(logout -> logout.logoutSuccessHandler((request, response, authentication) -> response.setStatus(200)));

        http.sessionManagement(policy -> policy.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // Adds custom authentication filter
        http.addFilter(authenticationFilter);

        // Adds custom authorization filter
        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public DefaultRedirectStrategy defaultRedirectStrategy() {
        return new DefaultRedirectStrategy();
    }

    @Bean
    public AuthenticationManager providerManager() {
        return new ProviderManager(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(bCryptPasswordEncoder);
        provider.setUserDetailsService(appUserService);
        provider.setHideUserNotFoundExceptions(false);
        return provider;
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return new CustomAuthenticationFailureHandler();
    }

    // Enables CORS for login endpoint
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**").allowedOrigins(origin);
            }
        };
    }

}
