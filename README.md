\# IoT Secure Transmission Lab



Prototipo experimental desarrollado como parte de un trabajo de Maestría en Ciberseguridad.



\## Descripción



El sistema implementa un esquema de protección criptográfica para comunicaciones IoT entre un microcontrolador ESP32 WROOM-32U y un servidor Flask.



El esquema combina:



\- ECDH sobre curva P-256 para establecimiento del secreto compartido.

\- HKDF-SHA256 para derivación de clave.

\- AES-256-GCM para cifrado autenticado.

\- Flask como backend para recepción, validación y descifrado.

\- Dashboard web para visualización de telemetría y evidencia criptográfica.



\## Arquitectura



Sensor MQ → ESP32 WROOM-32U → ECDH → HKDF-SHA256 → AES-256-GCM → HTTP/HTTPS → Flask → Dashboard



\## Seguridad



La clave privada ECC del servidor no se almacena en el repositorio.



El despliegue cloud utiliza mecanismos de gestión de secretos del proveedor de infraestructura.



\## Ejecución local



```bash

pip install -r requirements.txt

python server.py

