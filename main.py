"""
Script principal de GraphSec-IaC

Este script demuestra el uso del generador de grafos para analizar
proyectos de infraestructura como código.
"""

import os
import sys
from modules.graph_generator import generate_graph, get_graph_summary
from modules.security_scanner import scan_for_issues, get_sarif_summary

def main():
    """
    Función principal que ejecuta el generador de grafos.
    """
    
    # Ruta al directorio de prueba
    TEST_DIRECTORY = "./test_infra"
    SARIF_OUTPUT_FILE = "checkov_results.sarif"
    
    print("=== GraphSec-IaC - Análisis Completo de Infraestructura ===")
    print(f"Analizando directorio: {TEST_DIRECTORY}")
    print()
    
    # Verificar que el directorio de prueba existe
    if not os.path.exists(TEST_DIRECTORY):
        print(f"Error: El directorio {TEST_DIRECTORY} no existe")
        print("Asegurate de que el proyecto de Terraform de prueba este en la ubicacion correcta")
        return 1
    
    # Generar el grafo
    print("Generando grafo de infraestructura...")
    graph_data = generate_graph(TEST_DIRECTORY)
    
    # Verificar el resultado
    if graph_data is None:
        print("Error: No se pudo generar el grafo")
        print("Revisa los logs para mas detalles")
        return 1
    
    # Mostrar éxito y información del grafo
    print("Exito! Grafo generado correctamente")
    print()
    
    # Mostrar las claves principales del grafo
    print("Informacion del grafo:")
    print(f"   Claves del grafo: {list(graph_data.keys())}")
    
    # Mostrar resumen detallado
    summary = get_graph_summary(graph_data)
    print()
    print("Resumen del grafo:")
    for key, value in summary.items():
        print(f"   {key}: {value}")
    
    # Mostrar algunos nodos de ejemplo
    if "nodes" in graph_data and graph_data["nodes"]:
        print()
        print("Nodos encontrados:")
        for i, node in enumerate(graph_data["nodes"][:3]):  # Mostrar solo los primeros 3
            print(f"   {i+1}. {node.get('id', 'unknown')} ({node.get('type', 'unknown')})")
        
        if len(graph_data["nodes"]) > 3:
            print(f"   ... y {len(graph_data['nodes']) - 3} nodos mas")
    
    # Mostrar algunas aristas de ejemplo
    if "edges" in graph_data and graph_data["edges"]:
        print()
        print("Dependencias encontradas:")
        for i, edge in enumerate(graph_data["edges"][:3]):  # Mostrar solo las primeras 3
            source = edge.get('source', 'unknown')
            target = edge.get('target', 'unknown')
            print(f"   {i+1}. {source} -> {target}")
        
        if len(graph_data["edges"]) > 3:
            print(f"   ... y {len(graph_data['edges']) - 3} dependencias mas")
    
    print()
    
    # ===== ETAPA 2: ANÁLISIS DE SEGURIDAD =====
    print("=" * 50)
    print("ETAPA 2: ANÁLISIS DE SEGURIDAD")
    print("=" * 50)
    print()
    
    # Ejecutar escaneo de seguridad
    print("Ejecutando escaneo de seguridad con Checkov...")
    scan_success = scan_for_issues(TEST_DIRECTORY, SARIF_OUTPUT_FILE)
    
    if not scan_success:
        print("Error: No se pudo ejecutar el escaneo de seguridad")
        print("Continuando con el análisis del grafo...")
    else:
        print("Escaneo de seguridad completado exitosamente")
        print()
        
        # Mostrar resumen del archivo SARIF
        print("Procesando resultados del escaneo...")
        sarif_summary = get_sarif_summary(SARIF_OUTPUT_FILE)
        
        if "error" in sarif_summary:
            print(f"Error al procesar archivo SARIF: {sarif_summary['error']}")
        else:
            print("Resumen del escaneo de seguridad:")
            print(f"   Herramienta: {sarif_summary['tool_name']} v{sarif_summary['tool_version']}")
            print(f"   Total de resultados: {sarif_summary['total_results']}")
            print(f"   Reglas aplicadas: {sarif_summary['rules_count']}")
            print(f"   Archivos analizados: {sarif_summary['files_analyzed']}")
            print(f"   Timestamp: {sarif_summary['scan_timestamp']}")
            print()
            
            # Mostrar desglose por severidad
            if 'severity_breakdown' in sarif_summary:
                print("Desglose por severidad:")
                for severity, count in sarif_summary['severity_breakdown'].items():
                    print(f"   {severity}: {count}")
                print()
        
        print(f"Archivo SARIF generado: {SARIF_OUTPUT_FILE}")
        print()
    
    # ===== RESUMEN FINAL =====
    print("=" * 50)
    print("RESUMEN FINAL")
    print("=" * 50)
    print()
    
    if graph_data:
        print("Análisis de infraestructura: COMPLETADO")
        print(f"  - Nodos encontrados: {len(graph_data.get('nodes', []))}")
        print(f"  - Dependencias encontradas: {len(graph_data.get('edges', []))}")
    else:
        print("Análisis de infraestructura: FALLIDO")
    
    if scan_success:
        print("Análisis de seguridad: COMPLETADO")
        if "error" not in sarif_summary:
            print(f"  - Resultados encontrados: {sarif_summary['total_results']}")
            print(f"  - Archivo SARIF: {SARIF_OUTPUT_FILE}")
        else:
            print(f"  - Error: {sarif_summary['error']}")
    else:
        print("Análisis de seguridad: FALLIDO")
    
    print()
    print("Proceso completado exitosamente")
    return 0


if __name__ == "__main__":
    # Ejecutar la función principal
    exit_code = main()
    sys.exit(exit_code)
