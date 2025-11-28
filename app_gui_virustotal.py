# -*- coding: utf-8 -*-
"""
Ventana PyQt5 para analizar URLs con VirusTotal usando analizador.py

Requisitos:
    pip install PyQt5 requests
Archivos:
    - analizador.py  (tu módulo con la lógica de VirusTotal)
    - app_gui_virustotal.py  (este archivo)
"""

from PyQt5 import QtCore, QtGui, QtWidgets
import analizador  # Usa tu código existente (analizar_url, VirusTotalError, etc.)


# -------------------------- HELPERS DE LÓGICA -------------------------- #

def veredicto_desde_stats(stats: dict) -> str:
    """
    Misma lógica que en _veredicto_desde_stats de analizador.py,
    pero copiada aquí para no depender de una función "privada".
    """
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


# ------------------------------- UI PRINCIPAL ------------------------------- #

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(900, 650)

        self._main_window = MainWindow

        # --- Central widget y fuente base ---
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        MainWindow.setCentralWidget(self.centralwidget)

        base_font = QtGui.QFont()
        base_font.setPointSize(11)
        self.centralwidget.setFont(base_font)

        # -------------------- BLOQUE: INPUT URL + BOTÓN -------------------- #

        self.labelUrl = QtWidgets.QLabel("URL a analizar:", self.centralwidget)

        self.lineUrl = QtWidgets.QLineEdit(self.centralwidget)
        self.lineUrl.setPlaceholderText("Ej: https://ejemplo.com/phishing")
        self.lineUrl.setFixedHeight(42)
        self.lineUrl.setStyleSheet("QLineEdit { padding: 8px; }")

        # Validador simple de URL (permite letras, números y símbolos típicos de URLs)
        url_regex = QtCore.QRegExp(r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")
        self.lineUrl.setValidator(QtGui.QRegExpValidator(url_regex, self.lineUrl))

        self.btnAnalizar = QtWidgets.QPushButton("Analizar URL", self.centralwidget)
        self.btnAnalizar.setFixedHeight(42)
        self.btnAnalizar.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))

        url_layout = QtWidgets.QHBoxLayout()
        url_layout.setSpacing(10)
        url_layout.addWidget(self.labelUrl)
        url_layout.addWidget(self.lineUrl, 1)
        url_layout.addWidget(self.btnAnalizar)

        # -------------------- TABLA DE RESULTADOS -------------------- #
        # Columnas: URL, harmless, malicious, suspicious, undetected, Veredicto

        self.tableView = QtWidgets.QTableView(self.centralwidget)
        self.tableView.setObjectName("tableView")
        self.tableView.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tableView.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.tableView.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tableView.horizontalHeader().setStretchLastSection(True)
        self.tableView.verticalHeader().setVisible(False)
        self.tableView.setAlternatingRowColors(True)

        self.model = QtGui.QStandardItemModel(0, 6, self.tableView)
        self.model.setHorizontalHeaderLabels([
            "URL",
            "Harmless",
            "Malicious",
            "Suspicious",
            "Undetected",
            "Veredicto",
        ])
        self.tableView.setModel(self.model)

        header = self.tableView.horizontalHeader()
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)   # URL
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QtWidgets.QHeaderView.Stretch)   # Veredicto

        # -------------------- DETALLE EN TEXTO -------------------- #

        self.resultText = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.resultText.setReadOnly(True)
        self.resultText.setPlaceholderText("Aquí se mostrarán los detalles del último análisis...")
        self.resultText.setFixedHeight(170)

        # -------------------- BOTÓN CERRAR -------------------- #

        self.exitButton = QtWidgets.QPushButton("Cerrar", self.centralwidget)
        self.exitButton.setFixedWidth(120)
        self.exitButton.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))

        # -------------------- STATUS BAR -------------------- #

        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        MainWindow.setStatusBar(self.statusbar)

        # -------------------- LAYOUT PRINCIPAL -------------------- #

        main_layout = QtWidgets.QVBoxLayout(self.centralwidget)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(14)

        main_layout.addLayout(url_layout)
        main_layout.addWidget(self.tableView, 1)
        main_layout.addWidget(self.resultText, 0)

        bottom_layout = QtWidgets.QHBoxLayout()
        bottom_layout.addStretch(1)
        bottom_layout.addWidget(self.exitButton)
        main_layout.addLayout(bottom_layout)

        # -------------------- SEÑALES -------------------- #

        self.btnAnalizar.clicked.connect(self.analizar_url_gui)
        self.exitButton.clicked.connect(MainWindow.close)

        MainWindow.setWindowTitle("Detector de URLs sospechosas – VirusTotal")

    # -------------------- LÓGICA PRINCIPAL -------------------- #

    def analizar_url_gui(self):
        """Lee la URL del QLineEdit y llama al analizador de VirusTotal."""
        url = self.lineUrl.text().strip()

        if not url:
            self._warn("El campo 'URL a analizar' no puede estar vacío.")
            return

        # Si no tiene esquema, asumimos https://
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "https://" + url

        # Deshabilitar botón mientras se analiza
        self.btnAnalizar.setEnabled(False)
        self._info("Analizando URL con VirusTotal...")
        QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.WaitCursor)

        try:
            stats = analizador.analizar_url(url)
        except analizador.VirusTotalError as e:
            self._warn(str(e))
            return
        except Exception as e:
            # Cualquier otro error (network, HTTP 400, etc.)
            self._warn(f"Error al analizar la URL:\n{e}")
            return
        finally:
            QtWidgets.QApplication.restoreOverrideCursor()
            self.btnAnalizar.setEnabled(True)

        # Mostrar en tabla + texto
        self._mostrar_resultado(url, stats)

    def _mostrar_resultado(self, url: str, stats: dict):
        """Actualiza la tabla y el panel de texto con los resultados."""
        harmless = int(stats.get("harmless", 0))
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        undetected = int(stats.get("undetected", 0))
        veredicto = veredicto_desde_stats(stats)

        # --- Agregar fila a la tabla ---
        row_items = []

        it_url = QtGui.QStandardItem(url)
        row_items.append(it_url)

        def num_item(value: int) -> QtGui.QStandardItem:
            item = QtGui.QStandardItem(str(value))
            item.setTextAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
            return item

        row_items.append(num_item(harmless))
        row_items.append(num_item(malicious))
        row_items.append(num_item(suspicious))
        row_items.append(num_item(undetected))

        it_veredicto = QtGui.QStandardItem(veredicto)
        row_items.append(it_veredicto)

        self.model.appendRow(row_items)

        # --- Mostrar detalle en el panel de texto ---
        texto = [
            "== Resultado (URL – VirusTotal) ==",
            f"URL        : {url}",
            f"harmless   : {harmless}",
            f"malicious  : {malicious}",
            f"suspicious : {suspicious}",
            f"undetected : {undetected}",
            "-" * 40,
            f"Veredicto  : {veredicto}",
            ]
        self.resultText.setPlainText("\n".join(texto))

        # Mensajes al usuario
        self._info("Análisis completado.")
        QtWidgets.QMessageBox.information(
            self._main_window,
            "Análisis completado",
            f"Veredicto para la URL:\n\n{url}\n\n{veredicto}",
        )

    # -------------------- HELPERS UI -------------------- #

    def _info(self, text: str):
        self.statusbar.showMessage(text, 3000)

    def _warn(self, text: str):
        QtWidgets.QMessageBox.warning(self._main_window, "Advertencia", text)
        self.statusbar.showMessage(text, 4000)


# ------------------------------- EJECUCIÓN ------------------------------- #

if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
