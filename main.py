"""
Script principal de GraphSec-IaC

Este script demuestra el uso del generador de grafos para analizar
proyectos de infraestructura como código.
"""

import os
import sys
from modules.graph_generator import generate_graph, get_graph_summary
from modules.security_scanner import scan_for_issues, get_sarif_summary
from modules.correlation_engine import load_sarif_results, correlate_findings_to_graph, print_node_security_summary

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
    
    # ===== ETAPA 3: CORRELACIÓN =====
    print("=" * 50)
    print("ETAPA 3: CORRELACIÓN DE HALLAZGOS")
    print("=" * 50)
    print()
    
    # Verificar que tenemos tanto el grafo como el SARIF
    if graph_data and scan_success:
        print("Correlacionando hallazgos de seguridad con recursos de infraestructura...")
        
        # Cargar hallazgos de seguridad desde SARIF
        sarif_findings = load_sarif_results(SARIF_OUTPUT_FILE)
        
        if not sarif_findings:
            print("Error: No se pudieron cargar los hallazgos de seguridad")
        else:
            print(f"Cargados {len(sarif_findings)} hallazgos de seguridad")
            
            # Correlacionar hallazgos con el grafo
            enriched_graph = correlate_findings_to_graph(graph_data, sarif_findings)
            
            # Mostrar estadísticas de correlación
            correlation_metadata = enriched_graph.get("correlation_metadata", {})
            print(f"Correlación completada:")
            print(f"  - Hallazgos totales: {correlation_metadata.get('total_findings', 0)}")
            print(f"  - Nodos analizados: {correlation_metadata.get('total_nodes', 0)}")
            print(f"  - Correlaciones realizadas: {correlation_metadata.get('correlations_made', 0)}")
            print(f"  - Nodos con problemas: {correlation_metadata.get('nodes_with_issues', 0)}")
            print()
            
            # Buscar y mostrar problemas específicos del bucket S3
            print("Buscando problemas de seguridad en recursos específicos...")
            s3_bucket_found = False
            
            for node in enriched_graph.get("nodes", []):
                node_id = node.get("id", "")
                node_label = node.get("label", "")
                node_simple_name = node.get("simple_name", "")
                
                # Buscar el bucket S3 de prueba por diferentes identificadores
                if (("aws_s3_bucket" in node_id and "my_test_bucket" in node_id) or
                    ("aws_s3_bucket" in node_label and "my_test_bucket" in node_label) or
                    ("aws_s3_bucket" in node_simple_name and "my_test_bucket" in node_simple_name)):
                    print_node_security_summary(node)
                    s3_bucket_found = True
                    break
            
            if not s3_bucket_found:
                print("No se encontró el bucket S3 de prueba en el grafo")
                print("Nodos disponibles:")
                for i, node in enumerate(enriched_graph.get("nodes", []), 1):
                    node_id = node.get("id", "unknown")
                    node_label = node.get("label", "unknown")
                    node_simple_name = node.get("simple_name", "unknown")
                    print(f"  {i}. ID: {node_id}, Label: {node_label}, Simple: {node_simple_name}")
            
            print()
    else:
        print("No se puede realizar la correlación: faltan datos del grafo o del análisis de seguridad")
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
    
    # Mostrar estado de la correlación
    if graph_data and scan_success:
        print("Correlación de hallazgos: COMPLETADO")
        if 'enriched_graph' in locals():
            correlation_metadata = enriched_graph.get("correlation_metadata", {})
            print(f"  - Correlaciones realizadas: {correlation_metadata.get('correlations_made', 0)}")
            print(f"  - Nodos con problemas: {correlation_metadata.get('nodes_with_issues', 0)}")
        else:
            print("  - Error: No se pudo realizar la correlación")
    else:
        print("Correlación de hallazgos: FALLIDO")
    
    print()
    print("Proceso completado exitosamente")
    return 0


if __name__ == "__main__":
    # Ejecutar la función principal
    exit_code = main()
    sys.exit(exit_code)
