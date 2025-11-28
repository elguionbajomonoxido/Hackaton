import streamlit as st
import requests
import pandas as pd
import time
from urllib.parse import urlparse

# --- CONFIGURACIÓN DE LA PÁGINA ---
st.set_page_config(
    page_title="Detector de Veracidad y Riesgos",
    page_icon="🛡️",
    layout="centered"
)

# --- TU API KEY ---
API_KEY = "5ac5758d7316dfaf83261ef82fc13afd38a0bd64a39cc06330e6ab398d866575"

VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VT_URL_ANALYSIS = "https://www.virustotal.com/api/v3/analyses"

# --- BASE DE DATOS DE FUENTES CONFIABLES (JSON INTEGRADO) ---
# Aquí puedes agregar más dominios según necesites
BD_FUENTES_CONFIABLES = {
    "noticias": {
        "bbc.com": "BBC News (Internacional)",
        "cnn.com": "CNN (Internacional)",
        "elpais.com": "El País (España/Latam)",
        "elmundo.es": "El Mundo (España)",
        "nytimes.com": "The New York Times",
        "reuters.com": "Reuters (Agencia de noticias)",
        "latercera.com": "La Tercera (Chile)",
        "emol.com": "El Mercurio (Chile)",
        "eluniversal.com.mx": "El Universal (México)",
        "clarin.com": "Clarín (Argentina)"
    },
    "tecnologia": {
        "github.com": "GitHub (Código oficial)",
        "stackoverflow.com": "StackOverflow (Comunidad Dev)",
        "python.org": "Python Software Foundation",
        "microsoft.com": "Microsoft Oficial",
        "google.com": "Google Oficial"
    },
    "enciclopedias": {
        "wikipedia.org": "Wikipedia (Enciclopedia Libre)",
        "britannica.com": "Encyclopedia Britannica"
    }
}

# --- FUNCIONES DE UTILIDAD ---

def verificar_fuente_oficial(url):
    """
    Extrae el dominio y verifica si está en nuestra base de datos JSON de confianza.
    """
    try:
        # Extraer el dominio limpio (ej: www.google.com -> google.com)
        parsed_uri = urlparse(url)
        domain = parsed_uri.netloc.replace("www.", "").lower()
        
        # Buscar en las categorías
        for categoria, sitios in BD_FUENTES_CONFIABLES.items():
            if domain in sitios:
                return True, sitios[domain], categoria.capitalize()
            
            # Intento extra para subdominios (ej: chile.as.com -> as.com)
            parts = domain.split('.')
            if len(parts) > 2:
                root_domain = f"{parts[-2]}.{parts[-1]}"
                if root_domain in sitios:
                     return True, sitios[root_domain], categoria.capitalize()

        return False, None, None
    except:
        return False, None, None

def analizar_url_virustotal(url: str):
    if not API_KEY:
        return None, "Error: No hay API Key configurada."

    headers = {"x-apikey": API_KEY}
    
    # 1. Enviar URL
    data = {"url": url}
    try:
        resp = requests.post(VT_URL_SCAN, headers=headers, data=data, timeout=15)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        return None, f"Error de conexión: {e}"
        
    resp_json = resp.json()
    analysis_id = resp_json["data"]["id"]
    
    # 2. Esperar resultados
    max_retries = 10 
    with st.spinner('Consultando inteligencia de amenazas...'):
        for _ in range(max_retries):
            analysis_resp = requests.get(f"{VT_URL_ANALYSIS}/{analysis_id}", headers=headers, timeout=10)
            if analysis_resp.status_code == 200:
                analysis_data = analysis_resp.json()
                if analysis_data["data"]["attributes"]["status"] == "completed":
                    return analysis_data["data"]["attributes"]["stats"], None
            time.sleep(2)
            
    return None, "El análisis tardó demasiado."

def interpretar_riesgo(stats):
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    harmless = stats.get('harmless', 0)

    if malicious >= 3:
        nivel = "🔴 RIESGO CRÍTICO"
        explicacion = f"¡PELIGRO! {malicious} motores confirman malware. NO ACCEDER."
        color = "error"
    elif malicious > 0:
        nivel = "🟠 RIESGO ALTO"
        explicacion = f"Precaución. {malicious} motor(es) detectaron amenazas."
        color = "error"
    elif suspicious > 0:
        nivel = "🟡 RIESGO MEDIO"
        explicacion = f"Sitio sospechoso ({suspicious} alertas). Navega con cuidado."
        color = "warning"
    else:
        nivel = "🟢 TÉCNICAMENTE SEGURO"
        explicacion = f"Limpio de virus según {harmless} motores."
        color = "success"

    return nivel, explicacion, color

# --- INTERFAZ GRÁFICA ---

st.title("🛡️ Verificador de URLs & Fake News")
st.markdown("Analiza la seguridad técnica y verifica si la fuente es un medio reconocido.")

if 'history' not in st.session_state:
    st.session_state.history = []

url_input = st.text_input("URL a investigar:", placeholder="Ej: https://www.bbc.com/mundo")

if st.button("Analizar Fuente y Riesgos", type="primary"):
    if not url_input:
        st.warning("Por favor ingresa una URL.")
    else:
        url_to_check = url_input if url_input.startswith(("http://", "https://")) else "http://" + url_input
        
        # --- PASO 1: VERIFICACIÓN DE IDENTIDAD (Base de datos interna) ---
        es_oficial, nombre_sitio, categoria = verificar_fuente_oficial(url_to_check)
        
        if es_oficial:
            st.info(f"✅ **FUENTE VERIFICADA:** Este sitio está identificado en nuestra base de datos como **{nombre_sitio}** ({categoria}). Es una fuente de información reconocida.")
        else:
            st.caption("ℹ️ Esta URL no está en nuestra lista de medios verificados (esto es normal para blogs o sitios pequeños, pero ten precaución con noticias sensacionalistas).")

        # --- PASO 2: ANÁLISIS DE VIRUS (VirusTotal) ---
        stats, error = analizar_url_virustotal(url_to_check)

        if error:
            st.error(error)
        else:
            nivel, explicacion, color_msg = interpretar_riesgo(stats)

            if color_msg == "error":
                st.error(f"### {nivel}\n{explicacion}")
            elif color_msg == "warning":
                st.warning(f"### {nivel}\n{explicacion}")
            else:
                st.success(f"### {nivel}\n{explicacion}")

            # Datos duros
            c1, c2, c3 = st.columns(3)
            c1.metric("Maliciosos", stats.get('malicious', 0))
            c2.metric("Sospechosos", stats.get('suspicious', 0))
            c3.metric("Seguros", stats.get('harmless', 0))

            # Guardar historial
            st.session_state.history.insert(0, {
                "URL": url_to_check,
                "Fuente Oficial": "✅ Sí" if es_oficial else "No",
                "Riesgo": nivel
            })

# Tabla de historial
if st.session_state.history:
    st.divider()
    st.caption("Historial de sesión:")
    st.dataframe(pd.DataFrame(st.session_state.history), use_container_width=True)
