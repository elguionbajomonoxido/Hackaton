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

# --- TUS API KEYS ---
VT_API_KEY = "5ac5758d7316dfaf83261ef82fc13afd38a0bd64a39cc06330e6ab398d866575"
NEWS_API_KEY = "2042dec7997b4ae88cd9786d1d2ddbe1"  # ✅ Tu clave de NewsAPI agregada

VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VT_URL_ANALYSIS = "https://www.virustotal.com/api/v3/analyses"
NEWS_API_ENDPOINT = "https://newsapi.org/v2/everything"

# --- BASE DE DATOS LOCAL (Respaldo VIP) ---
BD_FUENTES_VIP = {
    "bbc.com": "BBC News",
    "cnn.com": "CNN",
    "elpais.com": "El País",
    "elmundo.es": "El Mundo",
    "nytimes.com": "New York Times",
    "wikipedia.org": "Wikipedia",
    "gob.cl": "Gobierno de Chile",
    "gob.mx": "Gobierno de México",
    "who.int": "OMS (Organización Mundial de la Salud)",
    "un.org": "Naciones Unidas"
}

# --- FUNCIONES ---

def limpiar_dominio(url):
    try:
        parsed = urlparse(url)
        # Devuelve 'bbc.com' de 'https://www.bbc.com/news'
        domain = parsed.netloc.replace("www.", "")
        return domain
    except:
        return ""

def verificar_reconocimiento_mediatico(domain):
    """
    Consulta a NewsAPI si este dominio produce noticias reconocidas.
    """
    if not NEWS_API_KEY:
        return None, "Falta API Key de NewsAPI"

    try:
        # Buscamos noticias recientes SOLAMENTE de este dominio
        params = {
            "domains": domain,
            "apiKey": NEWS_API_KEY,
            "pageSize": 1,  # Solo necesitamos saber si existe al menos 1 noticia reciente
            "language": "es" # Priorizamos español, puedes quitarlo para global
        }
        # Primera búsqueda estricta
        resp = requests.get(NEWS_API_ENDPOINT, params=params, timeout=5)
        data = resp.json()
        
        if data.get("status") == "ok":
            total_results = data.get("totalResults", 0)
            if total_results > 0:
                return True, f"Medio reconocido (NewsAPI encontró {total_results} artículos recientes)"
            else:
                # Intento secundario: buscar sin filtro de idioma por si es internacional (ej. TechCrunch)
                params.pop("language")
                resp_global = requests.get(NEWS_API_ENDPOINT, params=params, timeout=5)
                data_global = resp_global.json()
                if data_global.get("totalResults", 0) > 0:
                    return True, "Medio reconocido internacionalmente."
                
                return False, "El medio no aparece en los registros globales de noticias recientes."
        else:
            return False, "Error en la consulta a NewsAPI."
    except Exception as e:
        return False, f"Error de conexión: {e}"

def analizar_url_virustotal(url: str):
    if not VT_API_KEY:
        return None, "Error: No hay API Key de VirusTotal."

    headers = {"x-apikey": VT_API_KEY}
    
    # 1. Enviar URL
    try:
        resp = requests.post(VT_URL_SCAN, headers=headers, data={"url": url}, timeout=15)
        resp.raise_for_status()
    except Exception as e:
        return None, f"Error VT: {e}"
        
    analysis_id = resp.json()["data"]["id"]
    
    # 2. Polling (Esperar respuesta)
    for _ in range(10):
        resp = requests.get(f"{VT_URL_ANALYSIS}/{analysis_id}", headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data["data"]["attributes"]["status"] == "completed":
                return data["data"]["attributes"]["stats"], None
        time.sleep(2)
            
    return None, "Tiempo de espera agotado en VirusTotal."

def interpretar_riesgo(stats):
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    
    if malicious >= 2:
        return "🔴 PELIGROSO", "error"
    elif malicious == 1 or suspicious > 0:
        return "🟡 SOSPECHOSO", "warning"
    else:
        return "🟢 SEGURO", "success"

# --- INTERFAZ ---
st.title("🕵️ Validador de Noticias y Seguridad")
st.markdown("Verifica si un enlace es seguro y si proviene de un medio de comunicación real.")

if 'history' not in st.session_state:
    st.session_state.history = []

url_input = st.text_input("Ingresa la URL de la noticia:", placeholder="https://...")

if st.button("Analizar Veracidad y Riesgo", type="primary"):
    if not url_input:
        st.warning("Escribe una URL.")
    else:
        # Preparar URL
        if not (url_input.startswith("http://") or url_input.startswith("https://")):
            url_to_check = "https://" + url_input
        else:
            url_to_check = url_input
            
        domain = limpiar_dominio(url_to_check)
        
        col_izq, col_der = st.columns(2)
        
        # Declarar variables por defecto
        es_vip = False
        es_reconocido = False

        # --- ANÁLISIS 1: REPUTACIÓN DEL MEDIO ---
        with col_izq:
            st.subheader("📰 Fuente")
            
            # A) Chequeo VIP Local
            for d_vip, nombre in BD_FUENTES_VIP.items():
                if d_vip in domain:
                    st.success(f"✅ **Verificado:** {nombre}")
                    st.caption("Fuente oficial en nuestra Lista Blanca interna.")
                    es_vip = True
                    break
            
            # B) Chequeo NewsAPI (Si no es VIP)
            if not es_vip:
                es_reconocido, msg_news = verificar_reconocimiento_mediatico(domain)
                if es_reconocido:
                    st.info(f"✅ **Medio Activo:** {domain}")
                    st.caption("Este sitio publica noticias indexadas globalmente (Validado por NewsAPI).")
                else:
                    st.warning(f"❓ **Fuente Desconocida:** {domain}")
                    st.caption("No encontramos noticias recientes de este dominio en medios globales. Ten precaución.")

        # --- ANÁLISIS 2: CIBERSEGURIDAD ---
        with col_der:
            st.subheader("🛡️ Seguridad")
            stats, error = analizar_url_virustotal(url_to_check)
            
            if error:
                st.error("Error en VirusTotal")
                texto_riesgo = "Error"
            else:
                texto_riesgo, color = interpretar_riesgo(stats)
                if color == "error":
                    st.error(f"**{texto_riesgo}**")
                elif color == "warning":
                    st.warning(f"**{texto_riesgo}**")
                else:
                    st.success(f"**{texto_riesgo}**")
                
                st.metric("Motores Maliciosos", stats.get('malicious', 0))

        # Guardar historial
        estado_fuente = "✅ Oficial" if es_vip else ("✅ Medio Activo" if es_reconocido else "❓ Desconocido")
        
        st.session_state.history.insert(0, {
            "Dominio": domain,
            "Seguridad": texto_riesgo,
            "Fuente": estado_fuente
        })

if st.session_state.history:
    st.divider()
    st.dataframe(pd.DataFrame(st.session_state.history), use_container_width=True)
