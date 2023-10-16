package Cuscus.googleAuth.config;

import Cuscus.googleAuth.model.JwtProperties;
import Cuscus.googleAuth.security.jwt.JwtAuthenticationEntryPoint;
import Cuscus.googleAuth.security.jwt.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(JwtProperties.class)
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Autowired
    private JwtProperties jwtProperties;  // Inyecta las propiedades JWT

    @Autowired
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    RequestMatcher publicUrls = new OrRequestMatcher(
            new AntPathRequestMatcher("/auth/googleAuth"),
            new AntPathRequestMatcher("/vendedor/**")
    );

    RequestMatcher userUrls = new OrRequestMatcher(
            new AntPathRequestMatcher("/user/**")
    );

    RequestMatcher adminUrls = new OrRequestMatcher(
            Arrays.asList(
                    new AntPathRequestMatcher("/admin/**")
            )
    );

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable).cors(Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth
                                .requestMatchers(HttpMethod.OPTIONS).permitAll()
                                .requestMatchers(publicUrls).permitAll()
                                .requestMatchers(adminUrls).hasRole("ADMIN")
                                .requestMatchers(userUrls).hasRole("USER")
                )
                .sessionManagement(Customizer.withDefaults())
                .exceptionHandling(customize -> {
                    customize.authenticationEntryPoint(jwtAuthenticationEntryPoint); // Configuración del punto de entrada de autenticación
                })
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:3000"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowCredentials(true);  //
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
