Estado del Arte: La Convergencia de HackRF One, Inteligencia Artificial y Ciberseguridad Ofensiva en el Horizonte 2025
1. Prolegómenos Metodológicos: Hacia una Revisión Sistemática de Vanguardia
La presente investigación se articula bajo la premisa de generar un estado del arte exhaustivo y crítico para un Trabajo de Fin de Grado (TFG) centrado en la plataforma HackRF One y la tecnología de Radio Definida por Software (SDR). A diferencia de las revisiones bibliográficas convencionales, este reporte adopta una metodología dual rigurosa que integra una fase heurística de recolección y categorización taxonómica de la evidencia más reciente (2024-2025), y una fase hermenéutica de interpretación profunda, orientada a desentrañar las implicaciones subyacentes, las dinámicas adversariales emergentes y los vacíos epistemológicos en la literatura científica actual.
El objetivo no es meramente catalogar los avances técnicos, sino situar al HackRF One —un dispositivo que ha demostrado una resiliencia tecnológica notable— en el centro de un ecosistema de ciberseguridad que transita desde la guerra electrónica clásica hacia formas híbridas de explotación que involucran Inteligencia Artificial (IA), ataques a infraestructuras espaciales y la vulneración de sistemas ciberfísicos aislados (air-gapped). La revisión abarca fuentes primarias que incluyen papers académicos de conferencias de alto impacto (SpaceSec, ACM CCS, Black Hat), reportes de inteligencia de amenazas industriales y repositorios de desarrollo de firmware de código abierto, proporcionando una visión holística que trasciende la obsolescencia técnica aparente del hardware para revelar su vigencia operativa en el ciclo 2025.
1.1. Definición y Alcance de la Revisión Sistemática
En el contexto de este estudio, el "estado del arte" se define como el límite actual del conocimiento y la práctica tecnológica, donde la experimentación activa desafía los paradigmas de seguridad establecidos. Se ha priorizado la literatura y los desarrollos técnicos producidos entre enero de 2024 y el primer trimestre de 2025, un periodo crítico donde se observa la maduración de ataques sofisticados como TEMPEST-LoRa y la democratización del espionaje satelital. La selección de fuentes se ha realizado bajo criterios de relevancia técnica, novedad en el vector de ataque y reproducibilidad mediante hardware SDR de bajo coste.1
1.2. Distinción Epistemológica: Estado del Arte vs. Marco Teórico
Es imperativo establecer desde el inicio la distinción funcional entre el estado del arte presentado aquí y los componentes tradicionales de un trabajo académico:
Marco Teórico: Se ocupa de los fundamentos invariables (e.g., la teoría de muestreo de Nyquist-Shannon, la arquitectura de los transceptores superheterodinos o los principios matemáticos de la modulación QAM).
Antecedentes: Recopilan la historia cronológica de la tecnología (e.g., el lanzamiento original de HackRF en 2013 por Great Scott Gadgets o los primeros experimentos de replay simples).
Estado del Arte (Foco de este reporte): Analiza la frontera del conocimiento. No explica qué es la modulación LoRa, sino cómo se está utilizando en 2025 para exfiltrar datos de cables HDMI mediante emisiones electromagnéticas no intencionales capturadas por un HackRF.4 Examina cómo las limitaciones de hardware de hace una década se mitigan hoy mediante algoritmos de Deep Learning para RF Fingerprinting.5
2. Fase Heurística I: La Plataforma HackRF One en el Ecosistema SDR de 2025
La fase heurística de esta investigación se centra en la "arqueología" del presente tecnológico. A pesar de la proliferación de nuevas plataformas SDR, el HackRF One mantiene una posición hegemónica en la investigación de seguridad ofensiva. Sin embargo, su rol ha evolucionado: de ser un periférico de propósito general, se ha transformado en el núcleo de sistemas portátiles de ataque gracias a la evolución del firmware y los periféricos.
2.1. Análisis de la Arquitectura de Hardware frente a la Competencia Moderna
El HackRF One, con su arquitectura basada en el transceptor MAX2837 y el microcontrolador LPC43xx, presenta limitaciones físicas innegables en 2025, principalmente su resolución de 8 bits y su operación half-duplex. Sin embargo, la literatura reciente 6 sugiere que estas limitaciones son a menudo irrelevantes para vectores de ataque específicos (como el jamming o la inyección de señales digitales saturadas), o son compensadas por su inigualable rango de frecuencia (1 MHz a 6 GHz).
La comparación técnica con dispositivos contemporáneos como el ADALM-PLUTO, LimeSDR y la serie USRP B210 es fundamental para entender la selección de herramientas en proyectos de investigación actuales.
Parámetro Técnico
HackRF One
ADALM-PLUTO (Rev. C/D)
LimeSDR Mini 2.0
USRP B210
Rango Frecuencia
1 MHz – 6 GHz
325 MHz – 3.8 GHz (Extensible: 70 MHz – 6 GHz)
10 MHz – 3.5 GHz
70 MHz – 6 GHz
Modo Dúplex
Half-Duplex (Tx o Rx)
Full-Duplex (Tx y Rx simultáneos)
Full-Duplex (MIMO)
Full-Duplex (MIMO 2x2)
Ancho de Banda
20 MHz
20 MHz (USB 2.0 limitado)
40 MHz
56 MHz (USB 3.0)
Resolución ADC
8-bit
12-bit
12-bit
12-bit
Uso en 2025
Portabilidad (PortaPack), SIGINT táctico, Replay
Entornos educativos, OpenRAN, Jamming reactivo
Estaciones base LTE privadas, Sniffing
Investigación académica pura, Massive MIMO
Precio Relativo
Bajo-Medio
Bajo
Medio
Alto

La literatura de 2025 destaca una bifurcación en el uso:
Para aplicaciones sensibles a la latencia: Investigaciones como las de Hägglund y Slayingripper 9 señalan que la operación half-duplex del HackRF introduce una latencia de conmutación Rx/Tx que puede ser fatal para ataques que requieren una respuesta en microsegundos (e.g., protocolos de autenticación de desafío-respuesta rápidos en automoción o jamming reactivo inteligente). En estos casos, se prefiere el ADALM-PLUTO o el USRP.
Para cobertura espectral y portabilidad: El HackRF sigue siendo insuperable para ataques que requieren abarcar desde frecuencias bajas (como mandos de garaje en 315/433 MHz o RFID LF) hasta bandas altas de Wi-Fi (5.8 GHz) o enlaces satelitales en banda C, todo en un solo dispositivo económico.11
2.2. La Revolución del Firmware "Mayhem": De Periférico a Dispositivo de Borde (Edge Device)
Un hallazgo crítico de la fase heurística es que el "estado del arte" del HackRF no reside en su hardware, sino en la transformación radical impulsada por el ecosistema de firmware Mayhem para el módulo PortaPack (versiones H2, H2+, H4M). Durante 2024 y 2025, este firmware ha evolucionado para convertir al HackRF en una herramienta de ciberseguridad autónoma, eliminando la necesidad de un ordenador anfitrión para la mayoría de las operaciones de campo.13
El análisis de las releases más recientes (v2.0.0 a v2.2.0 y nightly builds de 2025) revela capacidades que redefinen el perfil de amenaza del dispositivo:
Apps Nativas de Decodificación y Ataque: El firmware ahora integra aplicaciones completas que se ejecutan en el microcontrolador ARM del dispositivo. Esto incluye decodificadores para ADS-B (con visualización de mapa en pantalla), receptores de imágenes satelitales NOAA APT y WeFax, y herramientas de jamming selectivo. La aplicación "Recon" permite la grabación automatizada de señales basada en umbrales de squelch, facilitando la inteligencia de señales (SIGINT) desatendida.15
Interfaz Web y Gestión Remota: La introducción de hackrf.app y la funcionalidad de Web Flasher basada en navegadores Chromium ha democratizado el mantenimiento del dispositivo. Más importante aún, la capacidad de gestión remota de archivos y visualización de pantalla a través de USB serial permite integrar el HackRF en sistemas automatizados de prueba o despliegues remotos.17
Nuevas Capacidades Operativas (2025): Se han añadido herramientas como "Hopper" (para saltos de frecuencia rápidos, útil para evasión o barrido espectral) y "Detector" (análisis de energía de banda ancha con historial), así como la capacidad de usar el dispositivo como un micrófono inalámbrico en frecuencias arbitrarias ("Microphone TX"), lo que tiene implicaciones directas en espionaje y operaciones de ingeniería social.16
2.3. Herramientas de Software y el Paradigma SDR++ / GNU Radio
En el lado del software de host, la hegemonía de GNU Radio se mantiene, pero la curva de aprendizaje se ha suavizado mediante herramientas de visualización como SDR++ e Inspectrum. SDR++ se ha establecido en 2024-2025 como el estándar para la exploración visual fluida debido a su arquitectura modular y eficiencia de recursos, permitiendo visualizar anchos de banda completos sin el overhead de software más antiguo como SDR#. Para el análisis profundo y la ingeniería inversa, herramientas como Universal Radio Hacker (URH) son citadas consistentemente en la literatura 20 como esenciales para la disección de protocolos propietarios (IoT, automoción) sin necesidad de conocimientos profundos de DSP, permitiendo a los investigadores pasar de la captura de señal (raw I/Q) a la manipulación de bits en minutos.
3. Fase Hermenéutica I: El Dominio Aeroespacial y la Vulnerabilidad Satelital
La interpretación de la literatura de 2025 revela una tendencia alarmante: la "democratización" de la guerra electrónica espacial. La disponibilidad de hardware como el HackRF One ha permitido a actores no estatales auditar y, potencialmente, comprometer infraestructuras satelitales que anteriormente se consideraban seguras por su lejanía física y complejidad tecnológica.
3.1. Intercepción de Telemetría en Constelaciones LEO (Low Earth Orbit)
Investigaciones presentadas en foros como SpaceSec 2025 y documentos técnicos del proyecto PWNSat 22 demuestran que gran parte de la nueva economía espacial ("NewSpace"), caracterizada por el uso de componentes COTS (Commercial Off-The-Shelf) y satélites pequeños (CubeSats), adolece de vulnerabilidades críticas en la capa física y de enlace.
3.1.1. Caso de Estudio: PWNSat y la Vulnerabilidad de Protocolos IoT en el Espacio
El análisis técnico del satélite experimental "PWNSat 0.1" ilustra cómo el HackRF One se utiliza para interceptar comunicaciones satelitales que emplean modulación LoRa y protocolos CCSDS (Consultative Committee for Space Data Systems) en bandas ISM (915 MHz).
Mecanismo de Intercepción: Los investigadores describen un flujo de trabajo replicable: uso de herramientas como rtl_power o el modo de barrido del HackRF para identificar picos espectrales; configuración de un flowgraph en GNU Radio que emplea bloques de sincronización de trama LoRa (Sync Word 0x12) y corrección de errores (FEC 4/5).
Implicaciones: La investigación confirma que la telemetría (estado de salud del satélite, datos de sensores BME280/MPU6050) a menudo se transmite sin cifrado de capa de aplicación, confiando erróneamente en la codificación de canal como mecanismo de seguridad. El HackRF One, actuando como una estación terrestre maliciosa, puede decodificar estos datos en tiempo real, exponiendo información operativa crítica.23
3.1.2. Fingerprinting de Transmisores Satelitales
Más allá de la intercepción de datos, la literatura de 2025 aborda el uso de técnicas de RF Fingerprinting para identificar satélites específicos dentro de una constelación. Utilizando SDRs para capturar las imperfecciones únicas del hardware de transmisión (desviaciones del oscilador, transitorios de encendido), los investigadores han logrado distinguir entre satélites legítimos y señales de spoofing generadas por otros SDRs, alcanzando tasas de éxito superiores al 98% en entornos controlados.22 Esto posiciona al HackRF no solo como herramienta de ataque, sino como un sensor vital para la defensa espacial y la conciencia situacional (SSA).
3.2. Spoofing GNSS y Amenazas a la Infraestructura Starlink
El spoofing de señales de navegación (GPS/GNSS) es una capacidad bien documentada del HackRF One, facilitada por librerías como gps-sdr-sim. Sin embargo, la investigación académica de 2025 ha desplazado el foco desde el engaño a vehículos individuales hacia el impacto sistémico en redes de comunicación globales. La tesis de Hägglund (2025) 9 investiga específicamente la resiliencia de los terminales de usuario de Starlink frente a ataques de suplantación GPS realizados con HackRF One. Dado que estos terminales phased-array requieren una geolocalización precisa y una sincronización temporal exacta para calcular los haces de seguimiento de satélites LEO de rápido movimiento, la inyección de coordenadas falsas o la deriva temporal inducida puede degradar severamente el rendimiento del enlace o causar la pérdida total de conectividad. Este hallazgo subraya una vulnerabilidad cruzada: atacar el sistema de posicionamiento para denegar el servicio de comunicaciones de banda ancha.24
4. Fase Hermenéutica II: La Superficie de Ataque en Automoción y Sistemas RKE
El sector de la automoción continúa siendo un campo de batalla prioritario para la investigación con SDR. En el periodo 2024-2025, la complejidad de los ataques ha aumentado en respuesta a las mejoras en los sistemas de entrada sin llave (RKE) y entrada pasiva (PKE).
4.1. De Replay Simple a RollJam y Protocolos Avanzados
Aunque los ataques de repetición (replay attacks) simples han sido mitigados en gran medida por el uso de códigos rodantes (rolling codes), la literatura reciente demuestra que el HackRF One sigue siendo eficaz mediante técnicas más avanzadas como RollJam.
Mecanismo RollJam: Este ataque emplea dos radios (o un HackRF y otro dispositivo) para bloquear (jamming) la recepción de la señal válida del mando mientras se captura el código enviado. El usuario, al ver que el coche no responde, pulsa el botón nuevamente. El atacante captura el segundo código y reproduce el primero (que sigue siendo válido porque el coche nunca lo recibió). Esto le permite al atacante guardar el segundo código válido para un uso futuro.
Evidencia Reciente: Estudios como los citados en 25 confirman que estas técnicas siguen siendo viables contra una amplia gama de vehículos (marcas A-D en los estudios) fabricados entre 2019 y 2023, especialmente aquellos que implementan implementaciones de rolling code propietarias y débiles en las bandas de 315 MHz y 433 MHz.
4.2. El Marco AutoGuardX y la Defensa Adaptativa
En respuesta a estas amenazas, la literatura de 2025 introduce marcos defensivos como AutoGuardX.27 Este sistema propone una arquitectura de seguridad integral que utiliza monitoreo en tiempo real del bus CAN y detección de anomalías en la capa física de RF para identificar intentos de inyección de señales o relay attacks. La relevancia del HackRF One en este contexto es doble:
Herramienta de Validación: Se utiliza en la fase de prueba (Fase 4 de la metodología AutoGuardX) para simular ataques y validar la eficacia del framework defensivo.
Referencia de Amenaza: AutoGuardX se diseña específicamente asumiendo que el adversario posee capacidades equivalentes a las de un HackRF o un Flipper Zero, estableciendo este nivel de capacidad como el estándar base de amenaza (baseline threat) para la industria automotriz moderna.
5. Fase Hermenéutica III: Canales Encubiertos y Física de Señales (TEMPEST)
Una de las áreas más innovadoras y técnicamente exigentes documentadas en la revisión es la explotación de emisiones electromagnéticas no intencionales para la exfiltración de datos desde sistemas aislados (air-gapped), reviviendo y modernizando el campo de TEMPEST.
5.1. TEMPEST-LoRa: La Pantalla como Transmisor de Radio
El ataque TEMPEST-LoRa, presentado en conferencias de seguridad de 2025 4, representa un cambio de paradigma en la seguridad física. Los investigadores demostraron que es posible manipular el hardware de video de un ordenador (tarjeta gráfica y cable VGA/HDMI) para emitir señales de radio controladas que imitan la modulación LoRa, sin necesidad de hardware de radio adicional en el equipo víctima.
Fundamento Técnico: El ataque explota el hecho de que los cables de video actúan como antenas no intencionales. Mediante la manipulación precisa de los registros de reloj de píxeles (e.g., modificando el registro 0xe1 mediante ddccontrol o software malicioso) y los patrones de imagen mostrados, se pueden generar armónicos en frecuencias específicas (como la banda ISM de 433 MHz o 868 MHz).
Rol del HackRF One: El HackRF One se utiliza como el receptor del lado del atacante. Debido a su alta sensibilidad y capacidad de sintonización fina, puede capturar estas emisiones extremadamente débiles a distancias de hasta 87.5 metros en condiciones ideales. El uso de SDR permite implementar receptores personalizados que pueden decodificar estas "señales de video" como si fueran paquetes de datos LoRa legítimos, permitiendo una tasa de exfiltración de datos baja pero efectiva (aprox. 21.6 bps) para robar claves de cifrado o credenciales.
Implicación Crítica: Este ataque demuestra que la protección de sistemas críticos mediante aislamiento físico (air-gapping) es insuficiente si no se considera el espectro electromagnético. El HackRF One se convierte así en una herramienta de espionaje avanzada capaz de violar perímetros físicos sin contacto.
6. Fase Hermenéutica IV: Infraestructura Crítica, SCADA e IoT Industrial
La convergencia de IT (Tecnología de la Información) y OT (Tecnología Operacional) ha expuesto a la infraestructura crítica a vectores de ataque inalámbricos. El HackRF One, con su capacidad para operar en bandas industriales ISM (900 MHz, 2.4 GHz), es una herramienta central en la investigación de vulnerabilidades en Smart Grids y sistemas SCADA.
6.1. Smart Grid y Advanced Metering Infrastructure (AMI)
La literatura de 2024-2025 30 destaca la vulnerabilidad de los medidores inteligentes (smart meters) a ataques de inyección de datos falsos. Muchos sistemas AMI utilizan redes de malla (mesh networks) inalámbricas propietarias o basadas en ZigBee para comunicar datos de consumo.
Oscilación de Carga (Load Oscillation Attack): Investigadores han modelado ataques donde un adversario utiliza un HackRF One para suplantar las señales de control de apagado/encendido de un grupo masivo de medidores inteligentes. Al conmutar simultáneamente miles de medidores (on/off) en una frecuencia resonante con la red eléctrica, es posible inducir inestabilidad en la frecuencia de línea y causar apagones en cascada. El HackRF facilita la ingeniería inversa de los comandos de control y la transmisión de alta potencia necesaria para inyectar estos comandos maliciosos.
6.2. Vulnerabilidades SCADA y Protocolos Propietarios
En el ámbito SCADA, se han reportado vulnerabilidades críticas en suites de software como ICONICS (CVE-2024-7587, CVE-2025-20014).33 Aunque estas son vulnerabilidades de software, la puerta de entrada a menudo involucra la intercepción de comunicaciones entre sensores remotos y el servidor SCADA central. El HackRF One permite a los investigadores (y atacantes) capturar tráfico de protocolos industriales (Modbus sobre RF, WirelessHART) para identificar credenciales por defecto o inyectar datos falsos que exploten estas vulnerabilidades de software en el backend.
7. Fase Hermenéutica V: Inteligencia Artificial y RF Fingerprinting
La integración de técnicas de Inteligencia Artificial con SDR representa la frontera más avanzada del estado del arte en 2025. El HackRF One se utiliza masivamente como dispositivo de adquisición de datos para entrenar modelos de Deep Learning (DL).
7.1. Identificación de Dispositivos (RF Fingerprinting)
El RF Fingerprinting busca identificar un dispositivo específico (e.g., "el HackRF del atacante A" vs "el HackRF del atacante B") basándose en las imperfecciones físicas únicas de su cadena de transmisión (ruido de fase, no linealidad del amplificador).
Avances 2025: Estudios recientes 5 utilizan el HackRF One para capturar datasets masivos de señales (Wi-Fi, Bluetooth, LoRa). Estos datos se alimentan a Redes Neuronales Convolucionales (CNN) para clasificar emisores con alta precisión.
Paradoja del HackRF: Curiosamente, el propio HackRF introduce "coloración" en las señales que captura debido a su hardware de bajo coste. La literatura discute cómo separar la huella del dispositivo emisor de la huella del dispositivo receptor (el HackRF), un desafío técnico que impulsa el desarrollo de algoritmos de corrección y calibración basados en IA.
7.2. Clasificación Automática de Modulación (AMC)
Proyectos conjuntos entre empresas como DeepSig y fabricantes de hardware 37 están llevando modelos de IA al borde. Aunque el HackRF no tiene capacidad de procesamiento para ejecutar estos modelos por sí mismo, es el sensor predilecto para alimentar sistemas basados en NVIDIA Jetson o FPGAs que realizan Clasificación Automática de Modulación (AMC) en tiempo real, permitiendo a sistemas de defensa identificar transmisiones hostiles en entornos electromagnéticos congestionados sin intervención humana.
8. Identificación de Vacíos Epistemológicos y Desafíos Técnicos
La revisión sistemática revela áreas donde la investigación es insuficiente o incipiente, ofreciendo oportunidades claras para el desarrollo de un TFG innovador:
Mitigación de Latencia en Hardware Half-Duplex: Existe un vacío notable en soluciones de software que compensen la latencia Rx/Tx del HackRF para aplicaciones críticas. La literatura tiende a sugerir "comprar mejor hardware" (e.g., USRP) en lugar de optimizar los drivers o el uso de buffers para exprimir el rendimiento del HackRF en escenarios de baja latencia.38
Estandarización de Datasets SDR: No existe un estándar universal para la creación y etiquetado de datasets de RF capturados con SDRs de bajo coste. La variabilidad entre unidades HackRF dificulta la reproducibilidad de los experimentos de IA. Un estudio que proponga métodos de normalización de señal para datasets heterogéneos sería una contribución significativa.36
Sistemas de Defensa SDR de Bajo Coste (WIDS): La mayoría de la literatura es ofensiva (Red Teaming). Hay una carencia de diseños de referencia para Sistemas de Detección de Intrusiones Inalámbricas (WIDS) distribuidos y baratos basados en HackRF que puedan detectar ataques como TEMPEST o spoofing de GPS en entornos corporativos o domésticos.35
Impacto del Ruido en Constelaciones Masivas: Falta investigación pública sobre cómo la interferencia de banda ancha generada por dispositivos SDR de consumo afecta a la constelación completa de satélites LEO (efecto agregado), más allá del ataque a un terminal individual.
9. Conclusiones y Perspectivas
El análisis del estado del arte en el periodo 2024-2025 confirma que el HackRF One, lejos de la obsolescencia, ha encontrado una segunda vida operativa. Su relevancia actual no se deriva de sus especificaciones brutas, que han sido superadas, sino de su integración en un ecosistema de software (Mayhem, GNU Radio, IA) que compensa sus deficiencias físicas con inteligencia computacional.
La plataforma se ha consolidado como el estándar de facto para la "guerra asimétrica del espectro": permite a investigadores y atacantes con recursos limitados desafiar la seguridad de sistemas multimillonarios, desde satélites en órbita hasta infraestructuras críticas nacionales. Para un Trabajo de Fin de Grado, el HackRF One ofrece un vehículo inigualable para explorar las vulnerabilidades de la sociedad hiperconectada, siempre que la investigación se enfoque no en el hardware per se, sino en las nuevas metodologías de ataque y defensa (IA, TEMPEST, protocolos espaciales) que este habilita. La evidencia sugiere que el futuro de la seguridad SDR no estará en radios más rápidas, sino en radios más inteligentes, capaces de aprender, adaptarse y operar de manera autónoma en un espectro cada vez más hostil.
Tabla Complementaria: Evolución Funcional del Firmware Mayhem (2024-2025)
Versión / Build
Fecha Aprox.
Características Clave y Nuevas Apps
Impacto en la Investigación
Mayhem v2.0.0
Q1 2024
Arquitectura de apps en SD, Web Flasher, USB Serial Web Interface.
Accesibilidad: Eliminó la barrera de entrada de drivers complejos. Permitió gestión remota.
Mayhem v2.1.0
Q3 2024
Web Apps offline, soporte BLE mejorado, correcciones de latencia UI.
Estabilidad: Viabilizó el uso en operaciones de campo prolongadas sin reinicios.
Mayhem v2.2.0
2025
App Manager, Detector (banda ancha con historial), WeFax/NOAA nativos.
Autonomía: Permite SIGINT satelital y meteorológica completa sin ordenador auxiliar.
Nightly 2025
Q1 2025
Hopper (salto de frecuencia), Microphone TX, mejoras en Recon.
Evasión: Introduce capacidades de LPI (Low Probability of Intercept) y vigilancia activa.

Obras citadas
Mid-Year Report 2025: An In-Depth Analysis of Evolving Ransomware and Weaponized ICS Malware | TXOne Networks, fecha de acceso: febrero 1, 2026, https://www.txone.com/white-papers/ransomware-ics-report-h1-2025/
Cyber Security 2025: Emerging Threats & Strategic Opportunities for MSPs and MSSPs, fecha de acceso: febrero 1, 2026, https://www.researchgate.net/publication/384724721_Cyber_Security_2025_Emerging_Threats_Strategic_Opportunities_for_MSPs_and_MSSPs
New Cybersecurity Rules for Radio Equipment: EU Regulation 2025/138 - WIoT Group, fecha de acceso: febrero 1, 2026, https://wiot-group.com/think/en/articles/new-eu-cybersecurity-for-radio-equipment/
TEMPEST-LoRa: Cross-Technology Covert Communication - arXiv, fecha de acceso: febrero 1, 2026, https://arxiv.org/html/2506.21069v1
Cyber Spectrum Intelligence: Security Applications ... - arXiv, fecha de acceso: febrero 1, 2026, https://arxiv.org/pdf/2501.03977
SDR Platforms Compared: USRP vs HackRF vs LimeSDR - Patsnap Eureka, fecha de acceso: febrero 1, 2026, https://eureka.patsnap.com/article/sdr-platforms-compared-usrp-vs-hackrf-vs-limesdr
Top 5 Software Defined Radios (SDR) for RF Experimentation - Wireless Pi, fecha de acceso: febrero 1, 2026, https://wirelesspi.com/top-5-software-defined-radios-sdr-for-rf-experimentation/
Comparing Software Defined Radios for Radio Astronomy, fecha de acceso: febrero 1, 2026, https://www.astronomy.me.uk/14335-2
Investigating Starlink's Resilience to GPS Spoofing and Space Weather Threats: Assessing the Impact of Man-Made and Natural Disruptions on Satellite Communication Performance - Simple search - DiVA portal, fecha de acceso: febrero 1, 2026, http://liu.diva-portal.org/smash/record.jsf?pid=diva2:1963494
Slayingripper/Investigating-Radio-Frequency-vulnerabilities-in-the-Internet-of-Things, fecha de acceso: febrero 1, 2026, https://github.com/Slayingripper/Investigating-Radio-Frequency-vulnerabilities-in-the-Internet-of-Things
A Comprehensive Lab Comparison between Multiple Software Defined Radios - RTL-SDR, fecha de acceso: febrero 1, 2026, https://www.rtl-sdr.com/a-comprehensive-lab-comparison-between-multiple-software-defined-radios/
Choosing SDR for radio astronomy - Google Groups, fecha de acceso: febrero 1, 2026, https://groups.google.com/g/sara-list/c/mi3aKKptLF0
portapack-mayhem/mayhem-firmware: Custom firmware for the HackRF+PortaPack H1/H2/H4 - GitHub, fecha de acceso: febrero 1, 2026, https://github.com/portapack-mayhem/mayhem-firmware
HackRF PortaPack H4M with Mayhem Firmware – A Powerful Handheld SDR Toolkit, fecha de acceso: febrero 1, 2026, https://www.mobile-hacker.com/2025/05/19/hackrf-portapack-h4m-with-mayhem-firmware-a-powerful-handheld-sdr-toolkit/
Mayhem v2.1.0 vs v2.2.0: New Features & Fixes - SDRstore, fecha de acceso: febrero 1, 2026, https://www.sdrstore.eu/mayhem-v2-1-0-vs-v2-2-0/
Portapack Mayhem V2.2.0 - Nilorea Studio, fecha de acceso: febrero 1, 2026, https://www.nilorea.net/2025/07/11/portapack-mayhem-v2-2-0/
Tech Minds: Taking a look at the new HackRF PortaPack Mayhem Version 2 Firmware, fecha de acceso: febrero 1, 2026, https://www.rtl-sdr.com/tech-minds-taking-a-look-at-the-new-hackrf-portapack-mayhem-version-2-firmware/
Portapack Mayhem 2.0.0 : r/hackrf - Reddit, fecha de acceso: febrero 1, 2026, https://www.reddit.com/r/hackrf/comments/1asilzz/portapack_mayhem_200/
Releases · portapack-mayhem/mayhem-firmware - GitHub, fecha de acceso: febrero 1, 2026, https://github.com/portapack-mayhem/mayhem-firmware/releases
Revisiting Wireless Cyberattacks on Vehicles - PMC - NIH, fecha de acceso: febrero 1, 2026, https://pmc.ncbi.nlm.nih.gov/articles/PMC12031412/
(PDF) Revisiting Wireless Cyberattacks on Vehicles - ResearchGate, fecha de acceso: febrero 1, 2026, https://www.researchgate.net/publication/390961874_Revisiting_Wireless_Cyberattacks_on_Vehicles
OrbID: Identifying Orbcomm Satellite RF Fingerprints - arXiv, fecha de acceso: febrero 1, 2026, https://arxiv.org/html/2503.02118v1
Interception and Eavesdropping of Satellite Communications | by ..., fecha de acceso: febrero 1, 2026, https://medium.com/@pwnsat/interception-and-eavesdropping-of-satellite-communications-b7be24d91ff8
Investigating Starlink's Resilience to GPS Spoofing and Space Weather Threats: Assessing the Impact of Man-Made and - Simple search, fecha de acceso: febrero 1, 2026, https://liu.diva-portal.org/smash/get/diva2:1963494/FULLTEXT01.pdf
MIT Open Access Articles Clonable key fobs: Analyzing and breaking RKE protocols, fecha de acceso: febrero 1, 2026, https://dspace.mit.edu/bitstream/handle/1721.1/159387/10207_2025_1063_ReferencePDF.pdf?sequence=1&isAllowed=y
AutoGuardX: A Comprehensive Cybersecurity Framework for Connected Vehicles - arXiv, fecha de acceso: febrero 1, 2026, https://arxiv.org/html/2508.18155v1
AutoGuardX: A Comprehensive Cybersecurity Framework for Connected Vehicles - arXiv, fecha de acceso: febrero 1, 2026, https://arxiv.org/html/2508.18155v2
AutoGuardX$: A Comprehensive Cybersecurity Framework for Connected Vehicles, fecha de acceso: febrero 1, 2026, https://www.researchgate.net/publication/394941412_AutoGuardX_A_Comprehensive_Cybersecurity_Framework_for_Connected_Vehicles
Air Gap | Hackaday, fecha de acceso: febrero 1, 2026, https://hackaday.com/tag/air-gap/
How hackers target smart meters to attack the grid - Netinium, fecha de acceso: febrero 1, 2026, https://www.netinium.com/how-hackers-target-smart-meters-to-attack-the-grid/
OSU researchers: smart meters can be hacked for power grid sabotage - KLCC, fecha de acceso: febrero 1, 2026, https://www.klcc.org/science-technology/2023-05-09/osu-researchers-smart-meters-can-be-hacked-for-power-grid-sabotage
Data falsification attacks in advanced metering infrastructure | Baskaran, fecha de acceso: febrero 1, 2026, https://beei.org/index.php/EEI/article/view/2024
SCADA Security — Latest News, Reports & Analysis, fecha de acceso: febrero 1, 2026, https://thehackernews.com/search/label/SCADA%20Security
Multiple vulnerabilities found in ICONICS industrial SCADA software - CyberScoop, fecha de acceso: febrero 1, 2026, https://cyberscoop.com/iconics-scada-vulnerabilities-2025-palo-alto/
Prediction-Based Spectrum Sensing Framework for Cognitive Radio - IEEE Xplore, fecha de acceso: febrero 1, 2026, https://ieeexplore.ieee.org/iel8/8784029/10830546/11142737.pdf
Robust Deep-learning-based Radio Fingerprinting with Fine-Tuning - GitHub, fecha de acceso: febrero 1, 2026, https://github.com/SmartHomePrivacyProject/RadioFingerprinting
DeepSig Partners with Epiq to Advance AI/ML Powered Spectrum Intelligence in Software Defined Radios, fecha de acceso: febrero 1, 2026, https://www.deepsig.ai/epiq-partnership-advance-ai-ml-powered-spectrum-intelligence/
Practical Realization of Reactive Jamming Attack on Long-Range Wide-Area Network - PMC, fecha de acceso: febrero 1, 2026, https://pmc.ncbi.nlm.nih.gov/articles/PMC12031409/
Practical Realization of Reactive Jamming Attack on LoRaWAN Network - Preprints.org, fecha de acceso: febrero 1, 2026, https://www.preprints.org/frontend/manuscript/949003ca2bc8297cea43855de89ab85a/download_pub
