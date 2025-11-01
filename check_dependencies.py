#!/usr/bin/env python3
"""
Script para verificar que todas las dependencias están instaladas correctamente
"""

import subprocess
import sys
import os

def check_command(command, name, install_instructions=""):
    """Verifica si un comando está disponible."""
    try:
        result = subprocess.run([command, "--version"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            version = result.stdout.strip().split('\n')[0]
            print(f"✅ {name}: {version}")
            return True
        else:
            print(f"❌ {name}: No disponible")
            if install_instructions:
                print(f"   Instrucciones: {install_instructions}")
            return False
    except FileNotFoundError:
        print(f"❌ {name}: No encontrado en PATH")
        if install_instructions:
            print(f"   Instrucciones: {install_instructions}")
        return False
    except Exception as e:
        print(f"❌ {name}: Error - {e}")
        return False

def main():
    """Verifica todas las dependencias."""
    print("🔍 Verificando dependencias de GraphSec-IaC...\n")
    
    # Verificar dependencias del sistema
    dependencies = [
        ("terraform", "Terraform", "Instala desde https://terraform.io/downloads"),
        ("dot", "Graphviz", "Windows: choco install graphviz | Linux: apt install graphviz | macOS: brew install graphviz"),
        ("trivy", "Trivy", "Windows: winget install aquasecurity.trivy | Linux: Ver install_trivy.md | macOS: brew install trivy"),
        ("python", "Python", "Instala desde https://python.org/downloads")
    ]
    
    all_good = True
    for command, name, instructions in dependencies:
        if not check_command(command, name, instructions):
            all_good = False
        print()
    
    # Verificar dependencias de Python
    print("🐍 Verificando dependencias de Python...")
    python_deps = [
        "fastapi",
        "uvicorn"
    ]
    
    for dep in python_deps:
        try:
            __import__(dep)
            print(f"✅ {dep}: Instalado")
        except ImportError:
            print(f"❌ {dep}: No instalado - pip install {dep}")
            all_good = False
    
    # Verificar Checkov en el venv específicamente
    print("🔍 Verificando Checkov en el venv...")
    try:
        import sys
        import os
        venv_path = os.path.join(os.path.dirname(__file__), 'venv', 'Scripts', 'checkov.cmd')
        if os.path.exists(venv_path):
            print("✅ Checkov: Instalado en venv")
        else:
            print("❌ Checkov: No encontrado en venv - pip install checkov")
            all_good = False
    except Exception as e:
        print(f"❌ Checkov: Error verificando - {e}")
        all_good = False
    
    print()
    
    if all_good:
        print("🎉 ¡Todas las dependencias están instaladas correctamente!")
        print("   Puedes ejecutar: python api.py")
    else:
        print("⚠️  Algunas dependencias faltan. Instálalas antes de continuar.")
        print("   Consulta install_trivy.md para más detalles.")
    
    return all_good

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
