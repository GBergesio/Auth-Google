package Cuscus.googleAuth.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/vendedor")
public class VendedorController {

    @GetMapping("/saludo")
    public ResponseEntity<?> saludo() {
        return new ResponseEntity<>("¡Bienvenido al endpoint no restringido!", HttpStatus.OK);
    }
}
