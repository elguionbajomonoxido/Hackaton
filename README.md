# Proyecto Python - Instrucciones de ejecución

Este repositorio contiene una aplicación Python cuyo punto de entrada principal es `main.py`. También incluye `analizador.py` y archivos relacionados con compilación (PyInstaller), por ejemplo `main.spec` y la carpeta `build/`.

**Secciones incluidas:**
- **Proyecto:** breve descripción y archivos relevantes.
- **Requisitos:** versiones y herramientas necesarias.
- **Instalación:** crear entorno virtual e instalar dependencias.
- **Ejecutar:** comandos para ejecutar en desarrollo.
- **Empaquetado:** cómo generar un ejecutable con PyInstaller.
- **Notas:** sugerencias y ubicación de artefactos de build.

## Proyecto

Punto de entrada: `main.py`.

Otros archivos importantes:
- `analizador.py` — módulo o script auxiliar.
- `main.spec` — especificación de PyInstaller (si desea empaquetar).
- `build/` — salida de builds previos de PyInstaller.

## Requisitos

- Python 3.8 o superior.
- `pip` para instalar dependencias.
- (Opcional) `pyinstaller` para empaquetar en un ejecutable.

Es recomendable trabajar en un entorno virtual.

## Instalación (PowerShell)

1. Crear y activar un entorno virtual:

```powershell
python -m venv .venv
# Activar en PowerShell
. .\.venv\Scripts\Activate.ps1
```

Si la política de ejecución de PowerShell impide ejecutar scripts, puede autorizar temporalmente:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

2. Actualizar `pip` e instalar dependencias (si existe `requirements.txt`):

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Si no existe `requirements.txt`, instale las dependencias necesarias manualmente:

```powershell
pip install <paquete1> <paquete2>
# una vez instaladas, puede exportarlas:
pip freeze > requirements.txt
```

## Ejecutar en desarrollo

Con el entorno activo, ejecute:

```powershell
python .\main.py
```

Si desea ejecutar `analizador.py` directamente (si es un script independiente):

```powershell
python .\analizador.py
```

## Empaquetado con PyInstaller

Si desea crear un ejecutable standalone, use `pyinstaller`. Si ya dispone de `main.spec`, puede usarlo directamente.

Instalar PyInstaller:

```powershell
pip install pyinstaller
```

Generar el ejecutable usando la especificación (recomendado si `main.spec` está presente):

```powershell
pyinstaller main.spec
```

O generar un único ejecutable desde `main.py`:

```powershell
pyinstaller --onefile main.py
```

Salida esperada:
- `dist\` — contendrá el ejecutable generado. Dependiendo de la configuración, el ejecutable puede estar en `dist\main.exe` o `dist\main\main.exe`.
- `build\` — archivos temporales de compilación (puede eliminarse si ya no hace falta).

Ejecutar el exe (PowerShell):

```powershell
# ejemplo si el ejecutable quedó como dist\main\main.exe
.\dist\main\main.exe
```

## Notas y recomendaciones

- Mantenga actualizados los paquetes listados en `requirements.txt`.
- Si el proyecto utiliza archivos de configuración o recursos externos, asegúrese de que la ruta relativa desde el ejecutable sea correcta (los builds pueden cambiar el working directory).
- Si tiene problemas con permisos en PowerShell al activar el entorno, use la línea de `Set-ExecutionPolicy` mostrada arriba.

## Próximos pasos sugeridos

- Añadir `requirements.txt` con dependencias exactas del proyecto (si falta).
- Probar `pyinstaller` para confirmar el comportamiento del ejecutable en Windows.
- Documentar variables de entorno o pasos especiales si la app los requiere.

---

Si desea, puedo:
- Generar un `requirements.txt` a partir del entorno actual.
- Ejecutar PyInstaller aquí y confirmar la ubicación del ejecutable.
- Ampliar el README con ejemplos de uso o instrucciones de debugging.

