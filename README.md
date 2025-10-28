# GraphSec-IaC

Una herramienta de orquestación para visualizar la seguridad en infraestructura como código (IaC).

## Descripción

GraphSec-IaC es una herramienta que combina la visualización de infraestructura con el análisis de seguridad, permitiendo correlacionar los resultados de escáneres de seguridad (como Checkov/Trivy) con la estructura de dependencias de la infraestructura generada por herramientas como Blast Radius.

## Arquitectura

El proyecto está dividido en tres etapas principales:

### Etapa 1: Generación de Grafos ✅
- **Módulo**: `modules/graph_generator.py`
- **Función**: Genera grafos de infraestructura usando `blast-radius` sobre proyectos de Terraform
- **Salida**: JSON con estructura de nodos, aristas y metadatos

### Etapa 2: Análisis de Seguridad ✅
- **Módulo**: `modules/security_scanner.py`
- **Herramienta**: Checkov
- **Formato**: Reportes SARIF
- **Función**: Escanear infraestructura en busca de vulnerabilidades y malas configuraciones
- **Salida**: Archivo SARIF con 7 vulnerabilidades detectadas en el bucket S3 de prueba

### Etapa 3: Correlación y Visualización ✅
- **Módulo**: `modules/correlation_engine.py`
- **Función**: Correlacionar hallazgos de seguridad con recursos de infraestructura
- **Algoritmo**: Correlación basada en tipo de recurso y análisis de mensajes
- **Salida**: Grafo enriquecido con 7 vulnerabilidades correlacionadas exitosamente

### Etapa 4: API y Frontend Web ✅
- **API**: `api.py` con FastAPI
- **Frontend**: `static/index.html` con visualización vis.js
- **Función**: Exponer funcionalidad a través de API RESTful y interfaz web
- **Características**: Visualización interactiva, nodos coloreados por vulnerabilidades, estadísticas en tiempo real

## Instalación

### Prerrequisitos

- Python 3.8+
- Terraform
- Graphviz
- Git

### Configuración del Entorno

```bash
# Clonar el repositorio
git clone https://github.com/guillermop2002/GraphSec-IaC.git
cd GraphSec-IaC

# Crear entorno virtual
python -m venv venv

# Activar entorno virtual
# Windows:
.\venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Instalar dependencias
pip install git+https://github.com/Ianyliu/blast-radius-fork

# Instalar Graphviz (Windows)
winget install Graphviz

# Instalar Terraform (Windows)
winget install Hashicorp.Terraform
```

## Uso

### Ejecutar la Aplicación Web

Con el entorno virtual activado y desde la raíz del proyecto:

```bash
# Iniciar el servidor web
uvicorn api:app --reload --host 127.0.0.1 --port 8000
```

Luego abre tu navegador y ve a: **http://127.0.0.1:8000**

### Ejecutar Análisis por Línea de Comandos (Opcional)

Si prefieres ejecutar el análisis sin interfaz web, puedes usar directamente los módulos:

```python
from modules.graph_generator import generate_graph
from modules.security_scanner import scan_for_issues
from modules.correlation_engine import load_sarif_results, correlate_findings_to_graph

# Ejecutar pipeline completo
graph_data = generate_graph("./test_infra")
scan_success = scan_for_issues("./test_infra", "checkov_results.sarif")
sarif_findings = load_sarif_results("checkov_results.sarif")
enriched_graph = correlate_findings_to_graph(graph_data, sarif_findings)
```

## Estructura del Proyecto

```
GraphSec-IaC/
├── modules/
│   ├── graph_generator.py       # Generador de grafos (Etapa 1)
│   ├── security_scanner.py      # Escáner de seguridad (Etapa 2)
│   └── correlation_engine.py    # Motor de correlación (Etapa 3)
├── static/
│   └── index.html              # Frontend web (Etapa 4)
├── api.py                      # API FastAPI (Etapa 4)
├── test_infra/
│   └── main.tf                 # Proyecto de prueba
├── checkov_results.sarif/      # Reportes de seguridad
├── venv/                       # Entorno virtual
└── README.md
```

## Estado del Proyecto

- ✅ **Etapa 1**: Generación de grafos implementada y funcionando
- ✅ **Etapa 2**: Análisis de seguridad implementado y funcionando
- ✅ **Etapa 3**: Correlación y visualización implementada y funcionando
- ✅ **Etapa 4**: API y frontend web implementados y funcionando

## Contribución

Este es un proyecto de TFG (Trabajo de Fin de Grado). Para contribuir, por favor contacta con el autor.

## Licencia

[Especificar licencia]
