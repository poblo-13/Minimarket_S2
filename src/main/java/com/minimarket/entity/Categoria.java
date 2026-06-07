package com.minimarket.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.List;

@Entity
public class Categoria {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Validacion de entrada (defensa en profundidad frente a XSS almacenado):
    // acotamos longitud y rechazamos los caracteres < y > usados en payloads HTML/script.
    @NotBlank
    @Size(max = 80)
    @Pattern(regexp = "^[^<>]*$", message = "El nombre no puede contener los caracteres < o >")
    @Column(nullable = false, unique = true)
    private String nombre;

    // Lado inverso: se ignora en la serializacion para romper el ciclo
    // Categoria <-> Producto (un Producto SI muestra su categoria, no al reves).
    @JsonIgnore
    @OneToMany(mappedBy = "categoria", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Producto> productos;

    // Getters y Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    public List<Producto> getProductos() {
        return productos;
    }

    public void setProductos(List<Producto> productos) {
        this.productos = productos;
    }
}
