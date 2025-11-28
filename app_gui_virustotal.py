import streamlit as st
import requests
import pandas as pd
import time

st.set_page_config(
    page_title="Detector de URLs - VirusTotal",
    page_icon="🛡️",
    layout="centered"
)

API_KEY = "5ac5758d7316dfaf83261ef82fc13afd38a0bd64a39cc06330e6ab398d866575"

VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VT_URL_ANALYSIS = "https://www.virustotal.com/api/v3/analyses"

def analizar_url_virustotal(url: str):
    if not API_KEY:
        return None, "Error: No hay API Key configurada."

    headers = {"x-apikey": API_KEY}
    
    data = {"url": url}
    try:
        resp = requests.post(VT_URL_SCAN, headers=headers, data=data, timeout=15)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        return None, f"Error al conectar con VirusTotal: {e}"
        
    resp_json = resp.json()
    analysis_id = resp_json["data"]["id"]
    
    max_retries = 30
    with st.spinner('VirusTotal está analizando la URL... espera un momento...'):
        for _ in range(max_retries):
            analysis_resp = requests.get(f"{VT_URL_ANALYSIS}/{analysis_id}", headers=headers, timeout=10)
            
            if analysis_resp.status_code == 200:
                analysis_data = analysis_resp.json()
                status = analysis_data["data"]["attributes"]["status"]
                
                if status == "completed":
                    return analysis_data["data"]["attributes"]["stats"], None
                
            time.sleep(2) 
            
    return None, "El análisis tardó demasiado. Inténtalo de nuevo."

def obtener_veredicto(stats: dict) -> str:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    
    if malicious > 0:
        return "⚠️ URL MALICIOSA"
    if suspicious > 0:
        return "⚠️ URL SOSPECHOSA"
    return "✅ Probablemente segura"

st.title("🛡️ Detector de URLs")
st.markdown("Analiza enlaces sospechosos usando la inteligencia de VirusTotal.")

if 'history' not in st.session_state:
    st.session_state.history = []

url_input = st.text_input("Ingresa la URL:", placeholder="http://sitio-sospechoso.com")

if st.button("Escanear URL", type="primary"):
    if not url_input:
        st.warning("Escribe una URL primero.")
    else:
        if not (url_input.startswith("http://") or url_input.startswith("https://")):
            url_to_check = "http://" + url_input
        else:
            url_to_check = url_input

        stats, error = analizar_url_virustotal(url_to_check)

        if error:
            st.error(error)
        else:
            veredicto = obtener_veredicto(stats)
            
            if "MALICIOSA" in veredicto:
                st.error(f"¡CUIDADO! {veredicto}")
            elif "SOSPECHOSA" in veredicto:
                st.warning(f"{veredicto}")
            else:
                st.success(f"{veredicto}")

            c1, c2, c3 = st.columns(3)
            c1.metric("Maliciosos", stats.get('malicious', 0))
            c2.metric("Sospechosos", stats.get('suspicious', 0))
            c3.metric("Seguros", stats.get('harmless', 0))

            st.session_state.history.insert(0, {
                "URL": url_to_check,
                "Resultado": veredicto,
                "Detecciones": stats.get('malicious', 0)
            })

if st.session_state.history:
    st.divider()
    st.caption("Historial reciente")
    st.dataframe(pd.DataFrame(st.session_state.history), use_container_width=True)
