import os
import requests

# Leer API key desde variable de entorno (recomendado)
API_KEY = "5ac5758d7316dfaf83261ef82fc13afd38a0bd64a39cc06330e6ab398d866575"

VT_URL = "https://www.virustotal.com/api/v3/urls"


class VirusTotalError(Exception):
    """Error específico para problemas con VirusTotal."""
    pass


def analizar_url_virustotal(url: str) -> dict:
    """
    Envía una URL a VirusTotal, espera el análisis
    y devuelve el dict de 'stats'.
    """
    if not API_KEY:
        raise VirusTotalError(
            "No hay API key configurada. Define la variable de entorno VT_API_KEY "
            "o edita analizador.py y pon tu clave en API_KEY."
        )

    resp = requests.post(
        VT_URL,
        headers={"x-apikey": API_KEY},
        data={"url": url},
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()

    analysis_id = data["data"]["id"]

    detalle = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers={"x-apikey": API_KEY},
        timeout=10,
    )
    detalle.raise_for_status()
    detalle_json = detalle.json()

    stats = detalle_json["data"]["attributes"]["stats"]

    return stats


def analizar_url(url: str) -> dict:
    return analizar_url_virustotal(url)


def _veredicto_desde_stats(stats: dict) -> str:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    if malicious > 0:
        return "⚠️ URL MALICIOSA"
    if suspicious > 0:
        return "⚠️ URL SOSPECHOSA"
    if harmless > 0 and malicious == 0 and suspicious == 0:
        return "✅ Probablemente segura (mayoría harmless)"
    if undetected > 0 and malicious == 0 and suspicious == 0:
        return "❓ Sin detecciones, pero tampoco marcada como harmless"

    return "❓ Veredicto incierto, revisa los detalles"


def imprimir_resultado(resultado):
    if not isinstance(resultado, dict):
        print(resultado)
        return

    tipo = resultado.get('type')

    if tipo == 'titular':
        print('\n== Resultado (Titular) ==')
        print('Texto:', resultado.get('text'))
        print('Longitud:', resultado.get('length'))
        print('Palabras sospechosas:', resultado.get('suspicious_words'))
        print('Puntuación (0..1):', resultado.get('score'))
        return

    if {"harmless", "malicious", "suspicious", "undetected"} & resultado.keys():
        print('\n== Resultado (URL – VirusTotal) ==')
        print('harmless   :', resultado.get('harmless', 0))
        print('malicious  :', resultado.get('malicious', 0))
        print('suspicious :', resultado.get('suspicious', 0))
        print('undetected :', resultado.get('undetected', 0))
        print('-' * 40)
        print(_veredicto_desde_stats(resultado))
        return

    print('\n== Resultado (Datos) ==')
    for k, v in resultado.items():
        print(f"{k}: {v}")
