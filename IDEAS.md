# Entidad de certificacion con openssl y prueba con servidor express.

## Arquitectura

1. OpenSSL
2. Server Express javascript.
3. Almacen de certificados del Mac para meter la ca.

## Funciones

1. crear la ca.
2. Crear una request de certificado de servidor para www.serverpruebas.localhost
4. Obtener el certificado de servidor.
5. Crear el api express configurado con el certificados obtenido publicado en el port 17433
6. Almacenar la ca en el almacen de certificados del Mac.

## Pruebas
Acceso al servidor web con el navegador usando agent-browser.
Acceso al servidor usando curl