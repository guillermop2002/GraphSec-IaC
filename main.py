"""
Script principal de GraphSec-IaC

Este script demuestra el uso del generador de grafos para analizar
proyectos de infraestructura como código.
"""

import os
import sys
from modules.graph_generator import generate_graph, get_graph_summary
from modules.security_analyzer import (
    run_checkov_analysis, 
    parse_checkov_results, 
    get_security_summary,
    get_high_severity_findings
)

def main():
    """
    Función principal que ejecuta el generador de grafos.
    """
    
    # Ruta al directorio de prueba
    TEST_DIRECTORY = "./test_infra"
    
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
    
    # Ejecutar análisis de seguridad
    print("Ejecutando análisis de seguridad con Checkov...")
    checkov_data = run_checkov_analysis(TEST_DIRECTORY)
    
    if checkov_data is None:
        print("Error: No se pudo ejecutar el análisis de seguridad")
        print("Continuando con el análisis del grafo...")
    else:
        print("Análisis de seguridad completado exitosamente")
        print()
        
        # Parsear resultados de seguridad
        print("Procesando resultados de seguridad...")
        security_report = parse_checkov_results(checkov_data)
        
        # Mostrar resumen de seguridad
        security_summary = get_security_summary(security_report)
        print("Resumen del análisis de seguridad:")
        print(f"   Total de checks: {security_summary['total_checks']}")
        print(f"   Checks pasados: {security_summary['passed_checks']}")
        print(f"   Checks fallidos: {security_summary['failed_checks']}")
        print(f"   Checks omitidos: {security_summary['skipped_checks']}")
        print(f"   Puntaje de seguridad: {security_summary['security_score']}/100")
        print(f"   Recursos afectados: {security_summary['affected_resources']}")
        print()
        
        # Mostrar hallazgos de alta severidad
        high_severity = get_high_severity_findings(security_report)
        if high_severity:
            print(f"Hallazgos de alta severidad ({len(high_severity)}):")
            for i, finding in enumerate(high_severity[:3], 1):  # Mostrar solo los primeros 3
                print(f"   {i}. {finding.check_name}")
                print(f"      Recurso: {finding.resource}")
                print(f"      Archivo: {finding.file_path}:{finding.file_line_range}")
                print(f"      ID: {finding.check_id}")
            
            if len(high_severity) > 3:
                print(f"   ... y {len(high_severity) - 3} hallazgos más")
            print()
        
        # Mostrar desglose por severidad
        print("Desglose por severidad:")
        for severity, count in security_summary['severity_breakdown'].items():
            print(f"   {severity}: {count}")
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
    
    if checkov_data:
        print("Análisis de seguridad: COMPLETADO")
        print(f"  - Vulnerabilidades encontradas: {security_summary['failed_checks']}")
        print(f"  - Puntaje de seguridad: {security_summary['security_score']}/100")
    else:
        print("Análisis de seguridad: FALLIDO")
    
    print()
    print("Proceso completado exitosamente")
    return 0


if __name__ == "__main__":
    # Ejecutar la función principal
    exit_code = main()
    sys.exit(exit_code)
