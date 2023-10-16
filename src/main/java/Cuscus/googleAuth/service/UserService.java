package Cuscus.googleAuth.service;

import Cuscus.googleAuth.model.Usuario;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;
import java.util.Optional;

public interface UserService {
    public void registerOrUpdateUser(String name, String email, String imageUrl);

    public Optional<Usuario> findByEmail(String email);

    public List<String> getRolesForUser(String email);

    public UserDetails loadUserByUsername(String email);
}
