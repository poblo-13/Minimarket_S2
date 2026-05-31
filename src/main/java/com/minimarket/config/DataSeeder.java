package com.minimarket.config;

import com.minimarket.entity.Rol;
import com.minimarket.entity.Usuario;
import com.minimarket.repository.RolRepository;
import com.minimarket.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Seeder de datos iniciales.
 *
 * Reemplaza al antiguo data.sql: en lugar de pegar un hash BCrypt quemado en el
 * SQL, aqui las contraseñas vienen del .env y se hashean en tiempo de ejecucion
 * con el mismo PasswordEncoder (BCrypt) que usa la app. Asi nunca se versiona un
 * hash en el repositorio y demostramos el uso programatico de BCrypt.
 */
@Component
public class DataSeeder implements CommandLineRunner {

    private final RolRepository rolRepository;
    private final UsuarioRepository usuarioRepository;
    private final PasswordEncoder passwordEncoder;

    // contraseñas desde el .env (con fallback de dev para no romper las pruebas de Postman)
    @Value("${seed.admin.password:12345}")
    private String adminPassword;

    @Value("${seed.empleado.password:12345}")
    private String empleadoPassword;

    @Value("${seed.cliente.password:12345}")
    private String clientePassword;

    public DataSeeder(RolRepository rolRepository,
                      UsuarioRepository usuarioRepository,
                      PasswordEncoder passwordEncoder) {
        this.rolRepository = rolRepository;
        this.usuarioRepository = usuarioRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        // idempotente: si ya hay usuarios no volvemos a sembrar (evita duplicados al reiniciar)
        if (usuarioRepository.count() > 0) {
            return;
        }

        // 1 creamos los tres roles del sistema
        Rol gerente = crearRol("GERENTE");
        Rol empleado = crearRol("EMPLEADO");
        Rol cliente = crearRol("CLIENTE");

        // 2 creamos un usuario por rol, hasheando la clave con BCrypt en codigo
        crearUsuario("admin", adminPassword, Set.of(gerente));
        crearUsuario("empleado", empleadoPassword, Set.of(empleado));
        crearUsuario("cliente", clientePassword, Set.of(cliente));
    }

    private Rol crearRol(String nombre) {
        return rolRepository.findByNombre(nombre).orElseGet(() -> {
            Rol rol = new Rol();
            rol.setNombre(nombre);
            return rolRepository.save(rol);
        });
    }

    private void crearUsuario(String username, String passwordPlano, Set<Rol> roles) {
        Usuario usuario = new Usuario();
        usuario.setUsername(username);
        usuario.setPassword(passwordEncoder.encode(passwordPlano)); // hashing BCrypt en runtime
        usuario.setRoles(roles);
        usuarioRepository.save(usuario);
    }
}
