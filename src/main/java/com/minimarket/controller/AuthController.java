package com.minimarket.controller;

import com.minimarket.dto.AuthRequest;
import com.minimarket.dto.AuthResponse;
import com.minimarket.dto.UsuarioDTO;
import com.minimarket.entity.Rol;
import com.minimarket.entity.Usuario;
import com.minimarket.repository.RolRepository;
import com.minimarket.repository.UsuarioRepository;
import com.minimarket.security.util.JwtUtil;
import com.minimarket.security.service.CustomUserDetailsService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Autowired
    private RolRepository rolRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody AuthRequest request) {
        // 1 evitamos registros duplicados
        if (usuarioRepository.findByUsername(request.getUsername()).isPresent()) {
            return ResponseEntity.status(409).body("Error: El nombre de usuario ya esta registrado");
        }

        // 2 todo usuario nuevo entra con el rol CLIENTE por defecto
        Rol rolCliente = rolRepository.findByNombre("CLIENTE")
                .orElseThrow(() -> new IllegalStateException("El rol CLIENTE no esta inicializado"));

        // 3 creamos el usuario hasheando la clave con BCrypt (nunca se guarda en texto plano)
        Usuario usuario = new Usuario();
        usuario.setUsername(request.getUsername());
        usuario.setPassword(passwordEncoder.encode(request.getPassword()));
        usuario.setRoles(Set.of(rolCliente));
        Usuario guardado = usuarioRepository.save(usuario);

        // 4 respondemos con un DTO: jamas exponemos la entidad ni el hash de la contraseña
        Set<String> roles = guardado.getRoles().stream()
                .map(Rol::getNombre)
                .collect(Collectors.toSet());
        UsuarioDTO dto = new UsuarioDTO(guardado.getId(), guardado.getUsername(), roles);
        return ResponseEntity.status(201).body(dto);
    }

    @PostMapping("/login")
    public ResponseEntity<?> createToken(@Valid @RequestBody AuthRequest request) {

        // JUGADA DE DEBUGGING
        System.out.println("EL HASH CORRECTO ES: " + new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().encode("12345"));
        // ---------------------------

        try {
            // 1 el guardia verifica si el usuario y la clave coinciden con la BD
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
        } catch (Exception e) {
            // manejo de error limpio sin mostrar el Stack Trace
            return ResponseEntity.status(401).body("Error: Credenciales incorrectas o usuario no existe");
        }

        // 2 Si pasa cargamos sus datos y sus roles
        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsername());
        Set<String> roles = userDetails.getAuthorities().stream()
                .map(auth -> auth.getAuthority().replace("ROLE_", ""))
                .collect(Collectors.toSet());

        // 3 fabricamos el Token JWT
        String jwt = jwtUtil.generateToken(userDetails.getUsername(), roles);

        // 4 se lo entregamos encapsulado en nuestro DTO
        return ResponseEntity.ok(new AuthResponse(jwt));
    }
}