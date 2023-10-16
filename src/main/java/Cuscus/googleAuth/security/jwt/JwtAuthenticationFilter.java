package Cuscus.googleAuth.security.jwt;

import Cuscus.googleAuth.model.JwtProperties;
import io.jsonwebtoken.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.List;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProperties jwtProperties;

    public JwtAuthenticationFilter(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String token = extractToken(request, chain, response);
        if (token == null) {
            return;
        }
        try {
            Claims claims = processJwtToken(token);
            setAuthentication(claims);
        } catch (MalformedJwtException e) {
            handleJwtError(response, "Token JWT mal formado o ausente");
            return;
        } catch (JwtException e) {
            handleJwtError(response, e.getMessage());
            return;
        }
        chain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request, FilterChain chain, HttpServletResponse response) throws IOException, ServletException {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return null;
        }
        return header.replace("Bearer ", "");
    }

    private Claims processJwtToken(String token) {
        return Jwts.parser()
                .setSigningKey(jwtProperties.getSecret())
                .parseClaimsJws(token)
                .getBody();
    }

    private void setAuthentication(Claims claims) {
        if (claims.getSubject() != null) {
            Object authoritiesObj = claims.get("authorities");
            if (authoritiesObj instanceof List<?> list) {
                List<SimpleGrantedAuthority> authorities = list.stream()
                        .filter(obj -> obj instanceof String)
                        .map(obj -> new SimpleGrantedAuthority((String) obj))
                        .toList();

                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(claims.getSubject(), null, authorities);
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }
    }

    private void handleJwtError(HttpServletResponse response, String errorMessage) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write("{\"message\": \"" + errorMessage + "\"}");
    }

}
