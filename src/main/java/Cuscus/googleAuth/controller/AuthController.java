package Cuscus.googleAuth.controller;

import Cuscus.googleAuth.security.jwt.JwtTokenUtil;
import Cuscus.googleAuth.service.UserService;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;

@RestController
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private GoogleIdTokenVerifier verifier;

    @Autowired
    private UserService userService;

    @Autowired
    JwtTokenUtil tokenUtil;

    @PostMapping("/googleAuth")
    public ResponseEntity<?> authenticateWithGoogle(@RequestBody Map<String, String> payload) throws GeneralSecurityException, IOException {
        String googleTokenId = payload.get("tokenId");

        if (googleTokenId == null || googleTokenId.isEmpty()) {
            return ResponseEntity.badRequest().body("Token no proporcionado");
        }

        GoogleIdToken idToken = verifier.verify(googleTokenId);
        if (idToken != null) {
            GoogleIdToken.Payload googleUser = idToken.getPayload();
            // Puedes extraer información del usuario de googleUser
            userService.registerOrUpdateUser((String) googleUser.get("name"), googleUser.getEmail(), (String) googleUser.get("picture"));
            // Cargar los detalles del usuario de la aplicación
            UserDetails userDetails = userService.loadUserByUsername(googleUser.getEmail());
            // Autenticar al usuario de la aplicación en Spring Security
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            //
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            // Obtener los roles del usuario desde tu sistema
            List<String> roles = userService.getRolesForUser(googleUser.getEmail());
            // Generar el token JWT
            String jwtToken = tokenUtil.generateTokenForUser(googleUser.getEmail(),roles);
            // Crea un objeto JSON con datos del usuario y el token JWT
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("token", jwtToken);
            responseData.put("userDetails", userDetails);
            responseData.put("authenticationToken", authenticationToken);

            return ResponseEntity.ok(responseData);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token de Google inválido");
        }
    }

}
