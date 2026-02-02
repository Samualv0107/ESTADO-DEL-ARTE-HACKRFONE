Estado del Arte: HackRF One y SDR en Ciberseguridad (Resumen 2025)
1. Evolución de la Plataforma y Firmware Mayhem
En el ciclo 2024-2025, el HackRF One mantiene su vigencia no por su hardware (que sigue siendo half-duplex de 8-bits), sino por la revolución del firmware Mayhem para PortaPack (H2/H4M). Este ecosistema ha transformado el dispositivo de un periférico USB a una herramienta de Edge Computing autónoma.   

Nuevas Capacidades (v2.2.0+): Se han integrado aplicaciones nativas como "Hopper" (saltos de frecuencia para evasión), "Detector" (análisis de energía de banda ancha con historial) y "Microphone TX" para vigilancia activa.

Gestión Remota: La introducción de la interfaz web hackrf.app y el Web Flasher permite la administración de archivos y visualización de pantalla remota, facilitando su uso en despliegues desatendidos.

2. Vulnerabilidades Espaciales y Satelitales (SpaceSec)
El HackRF se ha consolidado como el estándar para la auditoría de seguridad en el "NewSpace", democratizando la intercepción de satélites en órbita baja (LEO).

Intercepción de Telemetría: Investigaciones como PWNSat demuestran la captura de telemetría satelital no cifrada (protocolos CCSDS sobre modulación LoRa) en bandas ISM, permitiendo decodificar datos de sensores en tiempo real.   

Spoofing GNSS y Starlink: Se utiliza para inyectar coordenadas falsas que afectan la sincronización de terminales Starlink, degradando su capacidad de seguimiento satelital y conexión a internet.   

3. Vectores de Ataque en Automoción e IoT
A pesar de la modernización de los vehículos, el HackRF sigue siendo efectivo en ataques a sistemas de entrada sin llave (RKE).

Ataques Avanzados: Más allá del simple replay, se ejecutan técnicas de RollJam y relay contra vehículos fabricados entre 2019 y 2023, explotando implementaciones débiles de códigos rodantes en 315/433 MHz.   

Smart Grids: En infraestructura crítica, se modelan ataques de oscilación de carga (load oscillation) manipulando masivamente contadores inteligentes (Smart Meters) para desestabilizar la red eléctrica.   

4. Innovación en Canales Encubiertos: TEMPEST-LoRa
El estado del arte incluye técnicas de Air-Gap Bridging como TEMPEST-LoRa.

Mecanismo: El HackRF actúa como receptor sensible capaz de captar emisiones electromagnéticas no intencionales generadas por cables de video (HDMI/VGA). Los atacantes modulan la señal de video para que el cable actúe como una antena, transmitiendo datos exfiltrados que el HackRF decodifica como paquetes LoRa legítimos a distancia.   

5. Inteligencia Artificial y RF Fingerprinting
La integración con Deep Learning compensa las limitaciones de sensibilidad del hardware.

Identificación de Emisores: Se utiliza el HackRF para capturar datasets masivos que entrenan Redes Neuronales Convolucionales (CNN). Estas redes logran identificar dispositivos específicos (huella digital de RF) basándose en las imperfecciones únicas de su hardware de transmisión, alcanzando altas tasas de precisión en la clasificación de señales Wi-Fi y Bluetooth.

Conclusión para TFG: El HackRF One en 2025 es un habilitador de "guerra asimétrica del espectro". Su valor reside en la versatilidad del software que lo controla, permitiendo ejecutar ataques complejos (satelitales, TEMPEST, IA) con un coste de entrada mínimo.

