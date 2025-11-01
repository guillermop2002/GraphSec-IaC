# Instalación de Trivy para GraphSec-IaC

## Windows

### Opción 1: Usando WinGet (Recomendado)
```powershell
winget install aquasecurity.trivy
```

### Opción 2: Usando Chocolatey
```powershell
choco install trivy
```

### Opción 3: Descarga Manual
1. Ve a https://github.com/aquasecurity/trivy/releases
2. Descarga `trivy_X.X.X_windows-64bit.zip`
3. Extrae `trivy.exe` a una carpeta en tu PATH (ej: `C:\Program Files\Trivy\`)
4. Añade la carpeta al PATH del sistema

## Linux

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

### CentOS/RHEL
```bash
sudo rpm -ivh https://github.com/aquasecurity/trivy/releases/download/v0.67.2/trivy_0.67.2_Linux-64bit.rpm
```

## macOS

### Usando Homebrew
```bash
brew install trivy
```

## Verificación

Después de la instalación, verifica que Trivy funciona:
```bash
trivy --version
```

Deberías ver algo como:
```
Version: 0.67.2
```

## Configuración del PATH

Si Trivy no se encuentra automáticamente, asegúrate de que esté en tu PATH:

### Windows
1. Abre "Variables de entorno" desde el Panel de Control
2. Añade la ruta de Trivy al PATH del sistema
3. Reinicia tu terminal/IDE

### Linux/macOS
Añade a tu `~/.bashrc` o `~/.zshrc`:
```bash
export PATH=$PATH:/ruta/a/trivy
```

