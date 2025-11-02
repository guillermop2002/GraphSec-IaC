# GraphSec-IaC

Una herramienta de orquestación para visualizar la seguridad en infraestructura como código (IaC).

## Descripción

GraphSec-IaC es una herramienta que combina la visualización de infraestructura con el análisis de seguridad, permitiendo correlacionar los resultados de escáneres de seguridad (como Checkov/Trivy) con la estructura de dependencias de la infraestructura. Utiliza un parser nativo robusto y un motor de generación de grafos propio para garantizar máxima precisión y cobertura completa.

## Arquitectura

El proyecto está dividido en tres etapas principales:

### Etapa 1: Generación y Enriquecimiento de Grafos ✅
- **Módulos**: 
  - `modules/tf_parser.py`: Parser robusto de Terraform usando `python-hcl2` que extrae todos los recursos con metadatos precisos (líneas, rutas absolutas, texto crudo)
  - `modules/graph_builder.py`: 
    - Construye aristas (edges) analizando dependencias mediante expresiones regulares sobre el código Terraform
    - Enriquece nodos con metadatos precisos de archivo/líneas
- **Función**: Genera grafos de infraestructura completos (100% de cobertura de recursos) sin dependencias externas
- **Ventajas**: 
  - Control total sobre la generación del grafo
  - Incluye todos los recursos parseados (no ignora `data`, `provider`, etc.)
  - Metadatos precisos para correlación exacta
- **Salida**: JSON con estructura de nodos, aristas y metadatos de ubicación

### Etapa 2: Análisis de Seguridad ✅
- **Módulo**: `modules/security_scanner.py`
- **Herramientas**: Checkov y Trivy (múltiples escáneres)
- **Formato**: Reportes SARIF
- **Función**: Escanear infraestructura en busca de vulnerabilidades y malas configuraciones
- **Salida**: Archivos SARIF con hallazgos de seguridad de múltiples fuentes

### Etapa 3: Normalización (CIS), Filtrado y De-duplicación con CFI ✅
- **Módulo**: `modules/correlation_engine.py`
- **Funciones clave**:
  - `load_sarif_results(path)`: Carga SARIF y extrae `partialFingerprints` si existen
  - `_should_filter_finding(finding, project_root)`: Filtra inteligentemente ruido antes del procesamiento
  - `process_and_deduplicate_findings(findings, graph_data, project_root)`: Genera CFI, filtra ruido y de-duplica
  - `attach_findings_to_graph(graph_data, unique_findings)`: Adjunta hallazgos por recurso
- **Algoritmo**: CFI (Canonical Finding Identifier) basado en controles CIS normalizados + ubicación + resource_id; prioriza `partialFingerprints` cuando están presentes
- **De-duplicación**: Estable por CFI (independiente del texto del mensaje), elimina duplicados entre y dentro de escáneres
- **Filtrado inteligente** (`_should_filter_finding`):
  - Verifica que el archivo exista físicamente (filtra módulos remotos en cache)
  - Elimina hallazgos de `examples/`, `tests/` y archivos `.yml/.yaml`
  - Filtra módulos de Terraform Registry (`terraform-aws-modules/`) que no están en el código fuente
  - Filtra cache de Terraform (`.terraform/`)
- **Correlación por capas**:
  - **Capa 1 (Precisa)**: Correlación por rango de líneas exactas + rutas absolutas normalizadas. Requiere que el hallazgo esté dentro del rango `[start_line, end_line]` del nodo. **Resultado típico: 70-100% de los hallazgos**.
  - **Capa 2 (Filename)**: Fallback por coincidencia de nombre de archivo (ruta absoluta normalizada). Útil cuando el parser no capturó rangos precisos.
  - **Capa 3 (Semántica/CIS)**: Fallback conservador que solo asigna cuando hay exactamente 1 candidato único basado en tipo de recurso y regla CIS.
- **Normalización de rutas**: Usa rutas absolutas como fuente única de verdad, permitiendo comparación directa entre hallazgos SARIF y nodos del parser
- **Salida**: Grafo enriquecido con vulnerabilidades únicas correlacionadas exitosamente, estadísticas de distribución por capas, hallazgos no asignados (panel dedicado en frontend)

### Etapa 4: API y Frontend Web ✅
- **API**: `api.py` con FastAPI
- **Frontend**: `static/index.html` con visualización vis.js
- **Función**: Exponer funcionalidad a través de API RESTful y interfaz web
- **Características**: 
  - Visualización interactiva del grafo de infraestructura
  - Nodos coloreados por estado de vulnerabilidad (rojo: vulnerable, verde: seguro)
  - Estadísticas en tiempo real (hallazgos, nodos vulnerables, duplicados eliminados)
  - Panel dedicado para "Hallazgos No Asignados" con detalles completos
  - Soporte para múltiples proyectos (endpoints `/api/graph`, `/api/graph-vpc`, `/api/graph-eks`)

## ⚙️ Instalación

1. **Clona el repositorio:**
   ```bash
   git clone https://github.com/guillermop2002/GraphSec-IaC.git
   cd GraphSec-IaC
   ```

2. **(Opcional pero recomendado) Crea un entorno virtual:**
   ```bash
   python -m venv venv
   
   # Activar entorno virtual
   # Windows:
   .\venv\Scripts\activate
   # macOS/Linux:
   source venv/bin/activate
   ```

3. **Instala las dependencias de Python:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Dependencias Externas:** Esta herramienta requiere `terraform` y `trivy` en el PATH de tu sistema. Por favor, instálalos desde sus sitios web oficiales:
   - **Terraform**: https://www.terraform.io/downloads
   - **Trivy**: https://github.com/aquasecurity/trivy/releases

   **Nota para Windows**: Puedes instalar Terraform usando:
   ```bash
   winget install Hashicorp.Terraform
   ```

## 🚀 Uso (UI Local)

1. Abre tu terminal y navega al directorio raíz del proyecto (GraphSec-IaC).

2. Ejecuta el servidor web:

   ```bash
   python -m uvicorn api:app --reload
   ```

3. Abre tu navegador y visita una de las siguientes URLs:

   - **Proyecto de Prueba**: http://localhost:8000
   - **Proyecto VPC**: http://localhost:8000/?project=vpc
   - **Proyecto EKS**: http://localhost:8000/?project=eks

### Ejecutar Análisis por Línea de Comandos

Si prefieres ejecutar el análisis sin interfaz web, puedes usar el script CLI `run_pipeline.py`:

```bash
python run_pipeline.py --directory ./test_infra --project test_infra --output graph_data.json
```

Esto generará un archivo `graph_data.json` con el grafo enriquecido y los metadatos del análisis.

**Parámetros:**
- `-d, --directory`: Directorio del proyecto Terraform a analizar (requerido)
- `-p, --project`: Nombre del proyecto (para el caché) (requerido)
- `-o, --output`: Archivo JSON de salida (por defecto: `graph_data.json`)

### Uso Programático (Opcional)

Si necesitas usar los módulos directamente en tu código Python:

```python
from modules.tf_parser import parse_terraform
from modules.graph_builder import build_edges
from modules.security_scanner import CheckovScanner, TrivyScanner
from modules.correlation_engine import (
    load_sarif_results,
    process_and_deduplicate_findings,
    attach_findings_to_graph,
)

# Generar grafo
parsed_resources = parse_terraform("./mi-proyecto")
edges = build_edges(parsed_resources)
nodes = [
    {
        "id": r.get('simple_name'),
        "simple_name": r.get('simple_name'),
        "type": r.get('type'),
        "file": r.get('file'),
        "start_line": r.get('start_line'),
        "end_line": r.get('end_line'),
    }
    for r in parsed_resources
]
graph_data = {"nodes": nodes, "edges": edges}

# Ejecutar escáneres y cargar hallazgos SARIF
checkov_scanner = CheckovScanner()
trivy_scanner = TrivyScanner()
checkov_scanner.scan("./test_infra", "checkov_results.sarif")
trivy_scanner.scan("./test_infra", "trivy_results.sarif")

all_findings = []
all_findings.extend(load_sarif_results("checkov_results.sarif"))
all_findings.extend(load_sarif_results("trivy_results.sarif"))

# De-duplicación con CFI y adjunto al grafo
dedup = process_and_deduplicate_findings(all_findings, graph_data, project_root="./test_infra")
unique = dedup["unique_findings"]
enriched_graph = attach_findings_to_graph(graph_data, unique)
```

## 🔄 Integración CI/CD (GitHub Action)

GraphSec-IaC está diseñado para ejecutarse en un pipeline de CI/CD. Se incluye un fichero de ejemplo (`.github/workflows/security_analysis.yml`) que:

- Se activa en cada Pull Request hacia la rama `main`
- Instala todas las dependencias (Terraform, Trivy, Checkov)
- Ejecuta el script `run_pipeline.py` sobre el código
- Sube el `graph_data.json` resultante como un artefacto del workflow
- Publica un comentario en el Pull Request con un resumen de las métricas y un enlace para descargar el artefacto

### Visualización del Artefacto

Para ver el informe (`graph_data.json`) descargado del artefacto, simplemente abre el fichero `static/index.html` en tu navegador y cárgalo usando la función de carga de archivos JSON de la interfaz.

### Personalización del Workflow

Para analizar un directorio diferente (no `test_infra`), edita `.github/workflows/security_analysis.yml` y cambia:

```yaml
- name: Terraform Init
  run: terraform init -backend=false
  working-directory: ./tu-directorio  # Cambia esto

- name: Ejecutar Pipeline de GraphSec-IaC
  run: |
    python run_pipeline.py \
      --directory ./tu-directorio \  # Cambia esto
      --project mi_proyecto_pr_${{ github.event.pull_request.number }} \
      --output graph_data.json
```

## Estructura del Proyecto

```
GraphSec-IaC/
├── modules/
│   ├── tf_parser.py             # Parser robusto de Terraform usando python-hcl2 (Etapa 1)
│   ├── graph_builder.py         # Construcción de aristas y enriquecimiento de nodos (Etapa 1)
│   ├── security_scanner.py      # Escáner de seguridad multi-herramienta (Etapa 2)
│   ├── correlation_engine.py    # Motor de correlación, filtrado y de-duplicación (Etapa 3)
│   ├── utils.py                 # Utilidades (hashing para caché)
│   └── health_checker.py        # Verificación de dependencias externas
├── static/
│   └── index.html              # Frontend web con visualización interactiva (Etapa 4)
├── .github/
│   └── workflows/
│       └── security_analysis.yml # Workflow de GitHub Actions para CI/CD
├── tests/
│   └── unit/                   # Suite de tests unitarios
├── api.py                      # API FastAPI (Etapa 4)
├── run_pipeline.py             # Script CLI para ejecutar el pipeline
├── requirements.txt            # Dependencias de Python
├── test_infra/
│   └── main.tf                 # Proyecto de prueba
└── README.md
```

## Características Principales

### ✅ Parser Robusto de Terraform y Generación de Grafos Nativa
- Usa `python-hcl2` (parser oficial de HCL) para parsear archivos Terraform
- Maneja correctamente casos complejos: `count`, `for_each`, bloques dinámicos, comentarios
- Extrae metadatos precisos de ubicación (archivo, línea de inicio, línea de fin, texto crudo)
- Construye grafos nativos sin dependencias externas, analizando dependencias mediante expresiones regulares
- 100% de cobertura: incluye todos los recursos parseados (no ignora `data`, `provider`, etc.)

### ✅ Correlación Precisa por Capas
- **Capa 1 (Rango de líneas + filename)**: Correlación precisa usando rangos de líneas exactos del parser y rutas absolutas normalizadas. Método más preciso.
- **Capa 2 (Filename)**: Fallback cuando no hay rango preciso, usa coincidencia por nombre de archivo.
- **Capa 3 (Semántica/CIS)**: Fallback conservador que solo asigna cuando hay un único candidato claro basado en tipo de recurso y regla CIS.

### ✅ De-duplicación Inteligente con CFI
- Identificador Canónico de Hallazgo (CFI) basado en normalización CIS
- Prioriza `partialFingerprints` de SARIF cuando están disponibles
- Elimina duplicados entre diferentes escáneres (Checkov, Trivy)

### ✅ Filtrado Inteligente de Ruido
- Verifica que los archivos existan físicamente (filtra módulos remotos en cache)
- Elimina automáticamente hallazgos de directorios `examples/`, `tests/`
- Filtra archivos `.yml/.yaml` que no tienen nodos Terraform
- Filtra módulos de Terraform Registry en cache que no están en el código fuente
- **Resultado:** 0-5% de "No Asignados" vs ~30% con sistemas anteriores

### ✅ Multi-scanner Orchestration
- Ejecuta múltiples escáneres de seguridad (Checkov, Trivy)
- Combina resultados y aplica de-duplicación inteligente
- Muestra origen de cada hallazgo en la interfaz web

### ✅ Sistema de Caché para Optimización
- Caché inteligente basado en hash de archivos para grafos y resultados de escáneres
- Análisis repetidos en el mismo código son casi instantáneos
- Acelera el flujo de trabajo en desarrollo continuo

## Métricas de Éxito

GraphSec-IaC ha sido validado con tres proyectos de complejidad creciente:

### Resultados de Correlación (Promedio)
- **Capa 1 (Precisa)**: 95.12% de los hallazgos se correlacionan mediante rangos de líneas exactas
- **Capa 2 (Filename)**: 4.47% mediante coincidencia de archivo y línea más cercana
- **Capa 3 (Semántica)**: 0.00% mediante matching semántico conservador
- **No Asignados**: 0.41% (vs ~30% en sistemas anteriores)

### Efectividad de De-duplicación
- Eliminación eficiente de duplicados entre escáneres (Checkov ↔ Trivy)
- Reducción típica: 50-90% de hallazgos duplicados eliminados
- Método CFI garantiza estabilidad y precisión

### Cobertura de Recursos
- 100% de recursos parseados incluidos en el grafo (vs ~85% en sistemas basados en blast-radius)
- Incluye recursos no tradicionales: `data`, `provider`, `locals`, etc.
- Metadatos precisos (líneas, rutas absolutas) para correlación exacta

### Rendimiento
- Generación de grafos: < 5 segundos para proyectos grandes (EKS: 135 nodos, 83 aristas)
- Análisis completo (con caché): < 1 segundo para análisis repetidos
- Escalabilidad validada en proyectos complejos (terraform-aws-eks, terraform-aws-vpc)

## Estado del Proyecto

- ✅ **Etapa 1**: Generación y enriquecimiento de grafos implementado y funcionando
- ✅ **Etapa 2**: Análisis de seguridad multi-scanner implementado y funcionando
- ✅ **Etapa 3**: Correlación precisa y de-duplicación con CFI implementada y funcionando
- ✅ **Etapa 4**: API y frontend web implementados y funcionando

## 🧪 Pruebas

Este proyecto usa `pytest` para las pruebas unitarias y de integración.

Para ejecutar todas las pruebas:

```bash
python -m pytest
```

Para ejecutar pruebas específicas con más detalle:

```bash
python -m pytest -v
```

Para ejecutar un archivo de pruebas específico:

```bash
python -m pytest tests/unit/test_correlation_engine.py
```

## Contribución

Este es un proyecto de TFG (Trabajo de Fin de Grado). Para contribuir, por favor contacta con el autor.

## Licencia
