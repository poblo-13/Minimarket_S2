package com.minimarket.dto;

import java.util.Set;

public class UsuarioDTO {
    
    private Long id;
    private String username;
    private Set<String> roles; // solo enviaremos los nombres de los roles por seguridad

    public UsuarioDTO() {
    }

    public UsuarioDTO(Long id, String username, Set<String> roles) {
        this.id = id;
        this.username = username;
        this.roles = roles;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }
}