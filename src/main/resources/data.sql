-- 1 creamos el Rol de gerente
INSERT INTO rol (nombre) VALUES ('GERENTE');

-- 2 creamos al usuario 'admin' con la contraseña '12345' ya encriptada en BCrypt (Hash local)
INSERT INTO usuario (username, password) VALUES ('admin', '$2a$10$Cj2BHcrRNBXBuWWOcpSpWebu5mSiq5mnDiGSraHZwfxiAIlK8CR6i');

-- 3 le asignamos el rol al usuario
INSERT INTO usuario_roles (usuario_id, rol_id) VALUES (1, 1);