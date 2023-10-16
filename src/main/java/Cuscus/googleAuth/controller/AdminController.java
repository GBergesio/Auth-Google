package Cuscus.googleAuth.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {

    @GetMapping("/restricted")
    public ResponseEntity<?> restrictedEndpoint() {
        return new ResponseEntity<>("¡Bienvenido al endpoint restringido para administradores!", HttpStatus.OK);
    }

}
