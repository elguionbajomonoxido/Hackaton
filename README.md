# 🛡️ Detector de URLs - VirusTotal (Hackathon Edition)

Esta es una aplicación web interactiva desarrollada con **Streamlit** para analizar enlaces sospechosos en tiempo real utilizando la API de **VirusTotal**.

🔗 **[Click aquí para ver la App funcionando](https://hackatonisaias.streamlit.app)**

## 🚀 Novedades y Funcionalidades

* **Versión Web:** Migrado de escritorio (Qt) a Web (Streamlit) para fácil acceso desde cualquier dispositivo.
* **Análisis Robusto:** Implementa un sistema de espera inteligente (polling) para asegurar que VirusTotal termine el escaneo antes de mostrar resultados.
* **Historial de Sesión:** Muestra una tabla con las URLs analizadas recientemente.
* **Métricas Visuales:** Contadores claros de detecciones maliciosas, sospechosas y seguras.

## 🛠️ Tecnologías

* **Python 3**
* **Streamlit** (Framework de interfaz web)
* **Requests** (Comunicación con API)
* **Pandas** (Manejo de datos)

## 💻 Ejecución Local

Si deseas correr este proyecto en tu propia computadora en lugar de la web:

1.  **Clona el repositorio:**
    ```bash
    git clone [https://github.com/elguionbajomonoxido/Hackaton.git](https://github.com/elguionbajomonoxido/Hackaton.git)
    cd Hackaton
    ```

2.  **Instala los requisitos:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Ejecuta la aplicación:**
    ```bash
    streamlit run app_gui_virustotal.py
    ```

---
*Proyecto creado para el Hackathon 2025.*
