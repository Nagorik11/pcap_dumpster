Nombre del Proyecto: PcapStat-Analyzer
Objetivo Principal

Desarrollar una herramienta en Python que automatice el análisis de archivos de captura de paquetes (.pcap, .pcapng) para extraer estadísticas clave sobre el tráfico de red y presentar los resultados en un formato claro y legible (consola, HTML o PDF).
Funcionalidades Clave

El analizador deberá ser capaz de generar las siguientes estadísticas:

    Estadísticas Generales:

        Número total de paquetes.

        Tamaño total de la captura (en bytes/KB/MB).

        Duración de la captura (tiempo entre el primer y último paquete).

        Ancho de banda promedio (bytes/segundo).

    Análisis de Protocolos:

        Distribución de protocolos de capa de red (IP, ARP, etc.).

        Distribución de protocolos de capa de transporte (TCP, UDP, ICMP, etc.).

        Distribución de protocolos de aplicación (HTTP, DNS, TLS/SSL, etc.).

    Análisis de "Endpoints" y "Conversaciones":

        Top 10 de direcciones IP de origen y destino (quiénes son los que más hablan).

        Top 10 de conversaciones (pares de IP origen/destino con más tráfico).

        Top 10 de puertos TCP/UDP utilizados.

    Análisis Específico (Ejemplos):

        DNS: Listar todas las consultas DNS realizadas (los dominios que se buscaron).

        HTTP: Listar las peticiones HTTP (hosts, URLs solicitadas - solo si el tráfico no está cifrado).

        TLS/SSL: Extraer el "Server Name Indication" (SNI) de los handshakes de TLS para saber a qué dominios se conectan, incluso con tráfico cifrado.

    Generación de Reportes:

        Mostrar los resultados en la consola de forma organizada.

        (Avanzado) Generar un reporte en formato HTML o PDF con gráficos y tablas.

Tecnologías Recomendadas

    Lenguaje de Programación: Python 3. Es perfecto por su simplicidad y el gran ecosistema de librerías.

    Librerías Clave:

        Scapy: La librería más potente para leer, manipular y analizar paquetes. Es el corazón del proyecto. pip install scapy

        Pandas: Ideal para estructurar los datos extraídos de los paquetes en un DataFrame y realizar análisis estadísticos de forma muy sencilla. pip install pandas

        Matplotlib / Seaborn: Para generar gráficos (barras, tortas) que visualicen las estadísticas. pip install matplotlib seaborn

        GeoIP2 (Opcional): Para obtener la ubicación geográfica de las direcciones IP. pip install geoip2

        FPDF2 / Jinja2 (Opcional): Para generar reportes en PDF o HTML. pip install fpdf2 jinja2