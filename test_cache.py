"""
Script de prueba para verificar el funcionamiento del caché.
"""

import os
import json
import hashlib
from modules.utils import generate_hash_for_files
from modules.tf_parser import _iter_tf_files

# Directorio de caché
CACHE_DIR = ".graphsec_cache"
PIPELINE_VERSION = "v22.2"

def test_cache():
    """Prueba el sistema de caché."""
    
    print("=" * 80)
    print("PRUEBA DE CACHÉ")
    print("=" * 80)
    
    # 1. Verificar si existe el directorio de caché
    if not os.path.exists(CACHE_DIR):
        print(f"❌ El directorio de caché '{CACHE_DIR}' NO existe")
        print(f"   Se creará automáticamente cuando se ejecute el pipeline")
        return
    else:
        print(f"✅ El directorio de caché '{CACHE_DIR}' existe")
    
    # 2. Listar archivos en caché
    cache_files = []
    for root, dirs, files in os.walk(CACHE_DIR):
        for file in files:
            cache_files.append(os.path.join(root, file))
    
    if not cache_files:
        print(f"\n⚠️  No hay archivos en el caché")
        print(f"   Ejecuta el pipeline primero para generar el caché")
        return
    
    print(f"\n📁 Archivos en caché: {len(cache_files)}")
    for cache_file in sorted(cache_files)[:10]:  # Mostrar primeros 10
        rel_path = os.path.relpath(cache_file, CACHE_DIR)
        size = os.path.getsize(cache_file)
        print(f"   - {rel_path} ({size:,} bytes)")
    
    if len(cache_files) > 10:
        print(f"   ... y {len(cache_files) - 10} más")
    
    # 3. Probar el hash para un directorio específico
    test_directory = "./terraform-aws-eks"
    if not os.path.exists(test_directory):
        print(f"\n⚠️  El directorio de prueba '{test_directory}' no existe")
        print(f"   No se puede probar el hash")
        return
    
    print(f"\n🧪 Probando hash para: {test_directory}")
    tf_files = _iter_tf_files(test_directory)
    print(f"   Archivos .tf encontrados: {len(tf_files)}")
    
    if not tf_files:
        print(f"   ⚠️  No se encontraron archivos .tf")
        return
    
    # Generar hash
    graph_hash = generate_hash_for_files(tf_files)
    version_hash = hashlib.md5(PIPELINE_VERSION.encode()).hexdigest()[:8]
    
    print(f"   Hash de archivos: {graph_hash[:16]}...")
    print(f"   Hash de versión: {version_hash}")
    
    # 4. Buscar archivos de caché que coincidan con este hash
    project_name = "eks_pr_30"  # Cambiar si es necesario
    expected_cache_pattern = f"{project_name}_graph_{graph_hash}_{version_hash}.json"
    
    print(f"\n🔍 Buscando caché esperado: {expected_cache_pattern}")
    
    matching_files = [f for f in cache_files if project_name in f and "graph" in f]
    
    if matching_files:
        print(f"   ✅ Archivos de caché encontrados para '{project_name}':")
        for match_file in matching_files:
            rel_path = os.path.relpath(match_file, CACHE_DIR)
            print(f"      - {rel_path}")
            
            # Verificar si el hash coincide
            if graph_hash in rel_path:
                print(f"        ✅ Hash coincide")
                
                # Intentar cargar y verificar
                try:
                    with open(match_file, 'r', encoding='utf-8') as f:
                        cache_data = json.load(f)
                    nodes = cache_data.get('nodes', [])
                    edges = cache_data.get('edges', [])
                    print(f"        📊 Contenido: {len(nodes)} nodos, {len(edges)} aristas")
                except Exception as e:
                    print(f"        ❌ Error al leer: {e}")
            else:
                print(f"        ⚠️  Hash NO coincide (caché antiguo)")
    else:
        print(f"   ❌ No se encontraron archivos de caché para '{project_name}'")
        print(f"   Esto significa que el caché no se está usando")
        print(f"   Posibles causas:")
        print(f"     1. El nombre del proyecto cambió")
        print(f"     2. Los archivos .tf cambiaron (hash diferente)")
        print(f"     3. La versión del pipeline cambió")
    
    # 5. Probar hash dos veces para verificar consistencia
    print(f"\n🔄 Probando consistencia del hash (ejecutando 2 veces)...")
    hash1 = generate_hash_for_files(tf_files)
    hash2 = generate_hash_for_files(tf_files)
    
    if hash1 == hash2:
        print(f"   ✅ Hash es consistente: {hash1[:16]}...")
    else:
        print(f"   ❌ Hash NO es consistente!")
        print(f"      Hash 1: {hash1[:16]}...")
        print(f"      Hash 2: {hash2[:16]}...")
    
    # 6. Verificar qué archivos se incluyen en el hash
    print(f"\n📝 Archivos incluidos en el hash (primeros 10):")
    for i, tf_file in enumerate(sorted(tf_files)[:10]):
        print(f"   {i+1}. {os.path.relpath(tf_file, test_directory)}")
    if len(tf_files) > 10:
        print(f"   ... y {len(tf_files) - 10} más")
    
    # 7. Verificar tamaño del caché
    total_size = sum(os.path.getsize(f) for f in cache_files)
    print(f"\n💾 Tamaño total del caché: {total_size:,} bytes ({total_size / 1024 / 1024:.2f} MB)")
    
    print("\n" + "=" * 80)

if __name__ == "__main__":
    test_cache()

