import streamlit as st
import requests
import pandas as pd
import time

# --- CONFIGURACIÓN DE LA PÁGINA ---
st.set_page_config(
    page_title="Detector de URLs - VirusTotal",
    page_icon="🛡️",
    layout="centered"
)

# --- TU API KEY ---
API_KEY = "5ac5758d7316dfaf83261ef82fc13afd38a0bd64a39cc06330e6ab398d866575"

VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VT_URL_ANALYSIS = "https://www.virustotal.com/api/v3/analyses"

# --- LÓGICA DE ANÁLISIS ---
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
    
    # 2. Esperar resultados (Polling)
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

# --- NUEVA LÓGICA DE RIESGO Y EXPLICACIÓN ---
def interpretar_riesgo(stats):
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    harmless = stats.get('harmless', 0)

    # Nivel CRÍTICO: Muchos motores dicen que es virus
    if malicious >= 3:
        nivel = "🔴 RIESGO CRÍTICO"
        explicacion = (f"¡PELIGRO! {malicious} motores de seguridad han confirmado que esta página contiene malware, "
                       "phishing o software malicioso. NO accedas a este enlace bajo ninguna circunstancia.")
        color = "error"

    # Nivel ALTO: 1 o 2 motores detectaron algo
    elif malicious > 0:
        nivel = "🟠 RIESGO ALTO"
        explicacion = (f"Precaución. {malicious} motor(es) ha(n) marcado esta URL como maliciosa. "
                       "Podría ser un falso positivo, pero no es seguro navegar aquí.")
        color = "error"

    # Nivel MEDIO: Solo sospechas
    elif suspicious > 0:
        nivel = "🟡 RIESGO MEDIO"
        explicacion = (f"No se detectaron virus confirmados, pero {suspicious} motores consideran el sitio 'sospechoso'. "
                       "Puede tener contenido no ético o publicidad engañosa.")
        color = "warning"

    # Nivel BAJO: Todo limpio
    else:
        nivel = "🟢 SEGURO"
        explicacion = (f"La URL parece limpia. Ha sido analizada por {harmless} motores de seguridad y ninguno encontró amenazas.")
        color = "success"

    return nivel, explicacion, color

# --- INTERFAZ GRÁFICA ---
st.title("🛡️ Inspector de Riesgos Web")
st.markdown("Pega una URL para obtener un informe detallado de ciberseguridad.")

if 'history' not in st.session_state:
    st.session_state.history = []

url_input = st.text_input("URL a investigar:", placeholder="Ej: http://gane-un-iphone-gratis.com")

if st.button("Analizar Nivel de Riesgo", type="primary"):
    if not url_input:
        st.warning("Por favor ingresa una URL.")
    else:
        # Normalizar
        url_to_check = url_input if url_input.startswith(("http://", "https://")) else "http://" + url_input

        stats, error = analizar_url_virustotal(url_to_check)

        if error:
            st.error(error)
        else:
            # Obtener interpretación humana
            nivel, explicacion, color_msg = interpretar_riesgo(stats)

            # Mostrar resultado principal visualmente
            if color_msg == "error":
                st.error(f"### {nivel}\n\n{explicacion}")
            elif color_msg == "warning":
                st.warning(f"### {nivel}\n\n{explicacion}")
            else:
                st.success(f"### {nivel}\n\n{explicacion}")

            # Datos duros
            c1, c2, c3 = st.columns(3)
            c1.metric("Motores Maliciosos", stats.get('malicious', 0))
            c2.metric("Motores Sospechosos", stats.get('suspicious', 0))
            c3.metric("Motores Seguros", stats.get('harmless', 0))

            # Guardar historial
            st.session_state.history.insert(0, {
                "URL": url_to_check,
                "Riesgo": nivel,
                "Detalle": explicacion[:50] + "..." # Resumen para la tabla
            })

# Tabla de historial
if st.session_state.history:
    st.divider()
    st.caption("Últimos análisis realizados en esta sesión:")
    st.dataframe(pd.DataFrame(st.session_state.history), use_container_width=True)
