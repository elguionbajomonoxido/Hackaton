import streamlit as st
import requests
import pandas as pd

# --- CONFIGURACIÓN DE LA PÁGINA ---
st.set_page_config(
    page_title="Detector de URLs - VirusTotal",
    page_icon="🛡️",
    layout="centered"
)

# --- LÓGICA (Tu código original adaptado) ---
# IMPORTANTE: En producción, usa st.secrets para la API KEY.
# Por ahora la dejo aquí, pero lee la advertencia de seguridad al final del chat.
API_KEY = "5ac5758d7316dfaf83261ef82fc13afd38a0bd64a39cc06330e6ab398d866575"
VT_URL = "https://www.virustotal.com/api/v3/urls"

class VirusTotalError(Exception):
    pass

def analizar_url_virustotal(url: str) -> dict:
    if not API_KEY:
        raise VirusTotalError("No hay API key configurada.")

    headers = {"x-apikey": API_KEY}
    
    # 1. Enviar URL para escaneo
    resp = requests.post(VT_URL, headers=headers, data={"url": url}, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    analysis_id = data["data"]["id"]

    # 2. Obtener resultados del análisis
    detalle = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers,
        timeout=15,
    )
    detalle.raise_for_status()
    return detalle.json()["data"]["attributes"]["stats"]

def obtener_veredicto(stats: dict) -> str:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    if malicious > 0:
        return "⚠️ URL MALICIOSA"
    if suspicious > 0:
        return "⚠️ URL SOSPECHOSA"
    if harmless > 0:
        return "✅ Probablemente segura"
    if undetected > 0:
        return "❓ Sin detecciones conocidas"
    return "❓ Veredicto incierto"

# --- INTERFAZ DE USUARIO (Streamlit) ---

st.title("🛡️ Analizador de URLs - VirusTotal")
st.markdown("Ingresa una URL sospechosa para analizarla en tiempo real.")

# Inicializar historial en sesión
if 'history' not in st.session_state:
    st.session_state.history = []

# Input de URL
url_input = st.text_input("URL a analizar:", placeholder="https://ejemplo.com")

if st.button("Analizar URL", type="primary"):
    if not url_input:
        st.warning("Por favor ingresa una URL.")
    else:
        # Añadir protocolo si falta
        if not (url_input.startswith("http://") or url_input.startswith("https://")):
            url_to_check = "https://" + url_input
        else:
            url_to_check = url_input

        with st.spinner('Consultando a VirusTotal...'):
            try:
                stats = analizar_url_virustotal(url_to_check)
                veredicto = obtener_veredicto(stats)
                
                # Mostrar resultado grande
                if "MALICIOSA" in veredicto or "SOSPECHOSA" in veredicto:
                    st.error(f"Veredicto: {veredicto}")
                elif "segura" in veredicto:
                    st.success(f"Veredicto: {veredicto}")
                else:
                    st.info(f"Veredicto: {veredicto}")

                # Métricas
                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Harmless", stats.get('harmless', 0))
                col2.metric("Malicious", stats.get('malicious', 0))
                col3.metric("Suspicious", stats.get('suspicious', 0))
                col4.metric("Undetected", stats.get('undetected', 0))

                # Guardar en historial
                st.session_state.history.insert(0, {
                    "URL": url_to_check,
                    "Veredicto": veredicto,
                    "Malicious": stats.get('malicious', 0),
                    "Harmless": stats.get('harmless', 0)
                })

            except requests.exceptions.RequestException as e:
                st.error(f"Error de conexión: {e}")
            except VirusTotalError as e:
                st.error(str(e))
            except Exception as e:
                st.error(f"Ocurrió un error inesperado: {e}")

# Tabla de Historial
if st.session_state.history:
    st.divider()
    st.subheader("Historial de esta sesión")
    df = pd.DataFrame(st.session_state.history)
    st.dataframe(df, use_container_width=True)

