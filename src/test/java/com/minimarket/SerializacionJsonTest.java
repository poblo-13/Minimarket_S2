package com.minimarket;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.minimarket.entity.Categoria;
import com.minimarket.entity.DetalleVenta;
import com.minimarket.entity.Producto;
import com.minimarket.entity.Rol;
import com.minimarket.entity.Usuario;
import com.minimarket.entity.Venta;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regresion de seguridad/serializacion (defectos detectados en revision S3):
 *  1) Las entidades JPA con relaciones bidireccionales NO deben entrar en
 *     recursion infinita al serializarse a JSON (antes: "nesting depth 1001").
 *  2) El hash BCrypt de la contrasena NUNCA debe salir en la respuesta JSON,
 *     ni siquiera al serializar la entidad Usuario dentro de Venta/Carrito.
 *
 * Es un test puro de Jackson (sin contexto Spring) -> rapido y determinista.
 */
class SerializacionJsonTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private Usuario usuarioConHash() {
        Rol rol = new Rol();
        rol.setId(1L);
        rol.setNombre("CLIENTE");
        rol.setUsuarios(Set.of()); // lado inverso (debe ignorarse)

        Usuario usuario = new Usuario();
        usuario.setId(7L);
        usuario.setUsername("cliente");
        usuario.setPassword("$2a$10$hashBCryptSecretoQueNoDebeSalir");
        usuario.setRoles(Set.of(rol));
        // cerramos el ciclo Usuario <-> Rol
        rol.setUsuarios(Set.of(usuario));
        return usuario;
    }

    @Test
    void usuario_noExponeElHashDePassword() throws Exception {
        String json = mapper.writeValueAsString(usuarioConHash());
        assertFalse(json.contains("password"), "no debe aparecer el campo password");
        assertFalse(json.contains("hashBCryptSecretoQueNoDebeSalir"), "no debe filtrarse el hash");
        assertTrue(json.contains("\"username\":\"cliente\""), "el username si debe ir");
    }

    @Test
    void productoYCategoria_noEntranEnRecursion() {
        Categoria categoria = new Categoria();
        categoria.setId(1L);
        categoria.setNombre("Bebidas");

        Producto producto = new Producto();
        producto.setId(1L);
        producto.setNombre("Cola 1.5L");
        producto.setPrecio(1290.0);
        producto.setStock(20);
        producto.setCategoria(categoria);

        // ciclo Categoria <-> Producto
        categoria.setProductos(List.of(producto));

        assertDoesNotThrow(() -> {
            String jsonProducto = mapper.writeValueAsString(producto);
            assertTrue(jsonProducto.contains("\"categoria\""), "el producto si muestra su categoria");
            String jsonCategoria = mapper.writeValueAsString(categoria);
            assertFalse(jsonCategoria.contains("\"productos\""), "la categoria no expande productos (rompe el ciclo)");
        });
    }

    @Test
    void ventaCompleta_noEntraEnRecursion_niFiltraHash() {
        Categoria categoria = new Categoria();
        categoria.setId(1L);
        categoria.setNombre("Lacteos");

        Producto producto = new Producto();
        producto.setId(2L);
        producto.setNombre("Leche 1L");
        producto.setPrecio(990.0);
        producto.setStock(50);
        producto.setCategoria(categoria);
        categoria.setProductos(List.of(producto)); // ciclo categoria/producto

        Venta venta = new Venta();
        venta.setId(100L);
        venta.setUsuario(usuarioConHash());
        venta.setFecha(new Date(0));

        DetalleVenta detalle = new DetalleVenta();
        detalle.setId(1000L);
        detalle.setProducto(producto);
        detalle.setCantidad(2);
        detalle.setPrecio(990.0);
        detalle.setVenta(venta); // ciclo venta/detalle
        venta.setDetalles(List.of(detalle));

        assertDoesNotThrow(() -> {
            String json = mapper.writeValueAsString(venta);
            assertFalse(json.contains("password"), "la venta no debe filtrar el hash del usuario");
            assertTrue(json.contains("\"detalles\""), "la venta si muestra sus detalles");
            assertTrue(json.contains("Leche 1L"), "el detalle muestra el producto");
        });
    }
}
