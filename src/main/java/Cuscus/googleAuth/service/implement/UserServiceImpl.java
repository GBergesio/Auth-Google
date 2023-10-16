package Cuscus.googleAuth.service.implement;

import Cuscus.googleAuth.model.Usuario;
import Cuscus.googleAuth.repository.UserRepository;
import Cuscus.googleAuth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService, UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    @Override
    public void registerOrUpdateUser(String name, String email, String imageUrl) {
        Usuario usuario = userRepository.findByEmail(email).orElse(new Usuario());
        usuario.setName(name);
        usuario.setEmail(email);
        usuario.setImageUrl(imageUrl);
        // Solo establecer el rol si el ID del usuario es nulo, lo que indica que es un nuevo usuario
        if (usuario.getId() == null) {
            usuario.setRole("USER");
        }
        userRepository.save(usuario);
    }

    @Override
    public Optional<Usuario> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public List<String> getRolesForUser(String email) {
        // Implementa la lógica para obtener los roles de usuario
        Optional<Usuario> userOptional = userRepository.findByEmail(email);

        if (userOptional.isPresent()) {
            Usuario user = userOptional.get();

            List<String> roles = new ArrayList<>();
            roles.add(user.getRole());

            return roles;
        }

        // Si no se encuentra el usuario, puedes devolver un conjunto de roles predeterminados o lanzar una excepción según tu lógica de negocio.
        // Por ejemplo, aquí se devuelve un rol USER por defecto en caso de que el usuario no exista en la base de datos.
        return Collections.singletonList("USER");
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Usuario user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("No user found with email: " + email));

        List<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority(user.getRole()));

        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                "N/A",  // Contraseña ficticia o dummy
                authorities  // role convertido a GrantedAuthority
        );

    }
}
