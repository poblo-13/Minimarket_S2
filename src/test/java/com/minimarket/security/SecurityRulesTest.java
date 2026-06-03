package com.minimarket.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Pruebas de seguridad EJECUTADAS (criterios 4 y 5): verifican la matriz
 * rol x endpoint del SecurityConfig + @PreAuthorize. Cada autoridad se simula
 * con @WithMockUser(authorities=...) -> sin prefijo ROLE_, coherente con
 * CustomUserDetails y con el uso de hasAuthority/hasAnyAuthority en el codigo.
 *
 * Resultados esperados:
 *  - 200: acceso permitido para el rol
 *  - 403: autenticado pero sin el rol requerido (RestAccessDeniedHandler)
 *  - 401: sin autenticacion (RestAuthEntryPoint)
 */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityRulesTest {

    @Autowired
    private MockMvc mockMvc;

    // ---------- Sin token: 401 ----------

    @Test
    void sinToken_usuarios_da401() throws Exception {
        mockMvc.perform(get("/api/usuarios")).andExpect(status().isUnauthorized());
    }

    @Test
    void sinToken_productos_da401() throws Exception {
        mockMvc.perform(get("/api/productos")).andExpect(status().isUnauthorized());
    }

    // ---------- CLIENTE ----------

    @Test
    @WithMockUser(authorities = "CLIENTE")
    void cliente_leeCatalogo_da200() throws Exception {
        mockMvc.perform(get("/api/productos")).andExpect(status().isOk());
        mockMvc.perform(get("/api/categorias")).andExpect(status().isOk());
    }

    @Test
    @WithMockUser(authorities = "CLIENTE")
    void cliente_escribeCatalogo_da403() throws Exception {
        mockMvc.perform(post("/api/productos")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"nombre\":\"Galletas\",\"precio\":100,\"stock\":5}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(authorities = "CLIENTE")
    void cliente_usaCarrito_da200() throws Exception {
        mockMvc.perform(get("/api/carrito")).andExpect(status().isOk());
    }

    @Test
    @WithMockUser(authorities = "CLIENTE")
    void cliente_ventas_da403() throws Exception {
        mockMvc.perform(get("/api/ventas")).andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(authorities = "CLIENTE")
    void cliente_usuarios_da403() throws Exception {
        mockMvc.perform(get("/api/usuarios")).andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(authorities = "CLIENTE")
    void cliente_inventario_da403() throws Exception {
        mockMvc.perform(get("/api/inventario")).andExpect(status().isForbidden());
    }

    // ---------- EMPLEADO ----------

    @Test
    @WithMockUser(authorities = "EMPLEADO")
    void empleado_ventas_da200() throws Exception {
        mockMvc.perform(get("/api/ventas")).andExpect(status().isOk());
    }

    @Test
    @WithMockUser(authorities = "EMPLEADO")
    void empleado_inventario_da200() throws Exception {
        mockMvc.perform(get("/api/inventario")).andExpect(status().isOk());
    }

    @Test
    @WithMockUser(authorities = "EMPLEADO")
    void empleado_leeCatalogo_da200() throws Exception {
        mockMvc.perform(get("/api/productos")).andExpect(status().isOk());
    }

    @Test
    @WithMockUser(authorities = "EMPLEADO")
    void empleado_escribeCatalogo_da403() throws Exception {
        mockMvc.perform(post("/api/productos")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"nombre\":\"Galletas\",\"precio\":100,\"stock\":5}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(authorities = "EMPLEADO")
    void empleado_usuarios_da403() throws Exception {
        mockMvc.perform(get("/api/usuarios")).andExpect(status().isForbidden());
    }

    // ---------- GERENTE ----------

    @Test
    @WithMockUser(authorities = "GERENTE")
    void gerente_usuarios_da200() throws Exception {
        mockMvc.perform(get("/api/usuarios")).andExpect(status().isOk());
    }

    @Test
    @WithMockUser(authorities = "GERENTE")
    void gerente_inventario_da200() throws Exception {
        mockMvc.perform(get("/api/inventario")).andExpect(status().isOk());
    }

    @Test
    @WithMockUser(authorities = "GERENTE")
    void gerente_escribeCatalogo_da200() throws Exception {
        mockMvc.perform(post("/api/categorias")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"nombre\":\"Bebidas\"}"))
                .andExpect(status().isOk());
    }

    // ---------- Endpoint publico ----------

    @Test
    void publico_hola_sinToken_da200() throws Exception {
        mockMvc.perform(get("/public/hola")).andExpect(status().isOk());
    }
}
