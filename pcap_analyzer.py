#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PcapStat-Analyzer: Herramienta Automática de Análisis de Tráfico de Red

Este script analiza archivos de captura de paquetes (.pcap, .pcapng) para extraer
estadísticas clave y generar un reporte en consola y gráficos.

Funcionalidades:
- Estadísticas generales (total de paquetes, tamaño, duración).
- Distribución de protocolos de transporte.
- Top 10 de IPs, puertos y conversaciones.
- Extracción de consultas DNS.
- Extracción de Server Name Indication (SNI) de tráfico TLS (HTTPS).
- Generación de gráficos para una visualización rápida.

Uso desde la línea de comandos:
    python pcap_analyzer.py --file <ruta_al_archivo.pcap> --output <nombre_base_reporte>

Ejemplo:
    python pcap_analyzer.py --file mi_captura.pcap --output reporte_trafico

Dependencias:
    pip install scapy pandas matplotlib
"""

import argparse
import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP, TCP, UDP, DNS, TLS, TLSClientHello, TLSExtension
from collections import Counter
from datetime import datetime

# Desactivar advertencias de Scapy para una salida más limpia
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def format_bytes(size):
    """Convierte bytes a un formato legible (KB, MB, GB)."""
    power = 1024
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power and n < len(power_labels):
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"

class PcapAnalyzer:
    """
    Clase para analizar un archivo pcap y generar estadísticas.
    """
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = None
        self.df = None
        self.start_time = None
        self.end_time = None

    def _load_packets(self):
        """Carga los paquetes desde el archivo pcap."""
        print(f"[*] Cargando paquetes desde '{self.pcap_file}'...")
        try:
            self.packets = rdpcap(self.pcap_file)
            self.start_time = self.packets[0].time
            self.end_time = self.packets[-1].time
        except FileNotFoundError:
            print(f"[!] Error: El archivo '{self.pcap_file}' no fue encontrado.")
            return False
        except Exception as e:
            print(f"[!] Error al leer el archivo pcap: {e}")
            return False
        
        if not self.packets:
            print("[!] El archivo pcap está vacío o no se pudo leer.")
            return False
        
        print(f"[*] Carga completada. {len(self.packets)} paquetes encontrados.")
        return True

    def _parse_packets(self):
        """Extrae la información relevante de cada paquete y la almacena en un DataFrame."""
        print("[*] Analizando paquetes y extrayendo datos...")
        packet_data = []

        for packet in self.packets:
            if not packet.haslayer(IP):
                continue

            ip_layer = packet.getlayer(IP)
            
            info = {
                'timestamp': packet.time,
                'ip_src': ip_layer.src,
                'ip_dst': ip_layer.dst,
                'protocol': None,
                'src_port': None,
                'dst_port': None,
                'length': len(packet),
                'dns_query': None,
                'tls_sni': None
            }

            # Identificar protocolo de transporte y puertos
            if packet.haslayer(TCP):
                info['protocol'] = 'TCP'
                info['src_port'] = packet[TCP].sport
                info['dst_port'] = packet[TCP].dport
                # Extraer TLS SNI
                if packet.haslayer(TLSClientHello):
                    for ext in packet[TLSClientHello].extensions:
                        if isinstance(ext, TLSExtension) and ext.type == 0: # server_name
                            try:
                                info['tls_sni'] = ext.servernames[0].servername.decode('utf-8')
                            except Exception:
                                pass # Ignorar errores de decodificación
            elif packet.haslayer(UDP):
                info['protocol'] = 'UDP'
                info['src_port'] = packet[UDP].sport
                info['dst_port'] = packet[UDP].dport
                # Extraer consultas DNS
                if packet.haslayer(DNS) and packet[DNS].qr == 0: # 0 para consulta
                    try:
                        info['dns_query'] = packet[DNS].qd.qname.decode('utf-8')
                    except Exception:
                        pass # Ignorar errores
            else:
                info['protocol'] = ip_layer.proto

            packet_data.append(info)

        self.df = pd.DataFrame(packet_data)
        if self.df.empty:
            print("[!] No se encontraron paquetes con capa IP para analizar.")
            return False
            
        print("[*] Análisis completado.")
        return True

    def generate_report(self, output_basename, generate_plots=True):
        """Genera y muestra el reporte completo."""
        print("\n" + "="*50)
        print("          Reporte de Análisis de Tráfico de Red")
        print("="*50 + "\n")

        self._report_general_stats()
        self._report_protocol_distribution()
        self._report_endpoints_and_conversations()
        self._report_dns_queries()
        self._report_tls_sni()

        if generate_plots:
            self._generate_visualizations(output_basename)

    def _report_general_stats(self):
        print("[+] Estadísticas Generales:")
        print(f"    - Archivo Analizado: {self.pcap_file}")
        print(f"    - Número Total de Paquetes: {len(self.packets)}")
        total_size = sum(self.df['length'])
        print(f"    - Tamaño Total de la Captura: {format_bytes(total_size)}")
        duration = float(self.end_time - self.start_time)
        print(f"    - Duración de la Captura: {duration:.2f} segundos")
        print(f"    - Fecha de Inicio: {datetime.fromtimestamp(self.start_time)}")
        print(f"    - Fecha de Fin: {datetime.fromtimestamp(self.end_time)}")
        avg_bandwidth = total_size / duration if duration > 0 else 0
        print(f"    - Ancho de Banda Promedio: {format_bytes(avg_bandwidth)}/s\n")

    def _report_protocol_distribution(self):
        print("[+] Distribución de Protocolos de Transporte:")
        protocol_counts = self.df['protocol'].value_counts()
        print(protocol_counts.to_string())
        print("\n")

    def _report_endpoints_and_conversations(self):
        print("[+] Top 10 Direcciones IP de Origen:")
        print(self.df['ip_src'].value_counts().nlargest(10).to_string())
        print("\n[+] Top 10 Direcciones IP de Destino:")
        print(self.df['ip_dst'].value_counts().nlargest(10).to_string())
        print("\n[+] Top 10 Conversaciones (IP Origen -> IP Destino):")
        conversations = self.df.groupby(['ip_src', 'ip_dst']).size().nlargest(10)
        print(conversations.to_string())
        print("\n")

    def _report_dns_queries(self):
        print("[+] Top 10 Consultas DNS Realizadas:")
        dns_queries = self.df[self.df['dns_query'].notna()]['dns_query'].value_counts().nlargest(10)
        if not dns_queries.empty:
            print(dns_queries.to_string())
        else:
            print("    - No se encontraron consultas DNS.")
        print("\n")
        
    def _report_tls_sni(self):
        print("[+] Top 10 Dominios Visitados (TLS SNI):")
        tls_sni = self.df[self.df['tls_sni'].notna()]['tls_sni'].value_counts().nlargest(10)
        if not tls_sni.empty:
            print(tls_sni.to_string())
        else:
            print("    - No se encontraron handshakes de TLS con SNI.")
        print("\n")

    def _generate_visualizations(self, basename):
        """Genera y guarda los gráficos del análisis."""
        print("[*] Generando visualizaciones...")

        # Gráfico de Protocolos
        plt.figure(figsize=(10, 6))
        self.df['protocol'].value_counts().plot(kind='bar', color='skyblue')
        plt.title('Distribución de Protocolos')
        plt.xlabel('Protocolo')
        plt.ylabel('Número de Paquetes')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plot_path = f"{basename}_protocolos.png"
        plt.savefig(plot_path)
        plt.close()
        print(f"    - Gráfico guardado en: {plot_path}")

        # Gráfico de Top IPs de Origen
        plt.figure(figsize=(12, 8))
        self.df['ip_src'].value_counts().nlargest(10).plot(kind='barh', color='lightcoral')
        plt.title('Top 10 IP de Origen')
        plt.xlabel('Número de Paquetes')
        plt.ylabel('Dirección IP')
        plt.gca().invert_yaxis()
        plt.tight_layout()
        plot_path = f"{basename}_top_ips_origen.png"
        plt.savefig(plot_path)
        plt.close()
        print(f"    - Gráfico guardado en: {plot_path}")

    def run(self, output_basename, generate_plots):
        """Orquesta el proceso completo de análisis."""
        if not self._load_packets():
            return
        if not self._parse_packets():
            return
        
        self.generate_report(output_basename, generate_plots)

def main():
    parser = argparse.ArgumentParser(
        description="PcapStat-Analyzer: Herramienta de Análisis de Tráfico de Red.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-f", "--file",
        required=True,
        help="Ruta al archivo .pcap o .pcapng que se va a analizar."
    )
    parser.add_argument(
        "-o", "--output",
        default="reporte_analisis",
        help="Nombre base para los archivos de reporte generados (ej. gráficos)."
    )
    parser.add_gument(
        "--no-plots",
        action="store_true",
        help="Desactiva la generación de gráficos."
    )
    
    args = parser.parse_args()
    
    analyzer = PcapAnalyzer(args.file)
    analyzer.run(args.output, not args.no_plots)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Análisis interrumpido por el usuario. Saliendo.")