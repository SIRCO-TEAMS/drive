import sys
import os
import json
import requests
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit,
    QPushButton, QLabel, QListWidget, QListWidgetItem, QFileDialog, QInputDialog,
    QMessageBox, QProgressBar, QMenu, QAction, QDialog, QFormLayout, QComboBox
)
from PyQt5.QtCore import Qt, QTimer

SETTINGS_FILE = os.path.join(os.path.dirname(__file__), "ftpwebclient_py_settings.json")

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)
    return {"presets": {}, "last_url": ""}

def save_settings(settings):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f)

class SettingsDialog(QDialog):
    def __init__(self, parent, settings):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.settings = settings
        layout = QFormLayout()
        self.url_input = QLineEdit(self)
        self.url_input.setText(settings.get("last_url", ""))
        layout.addRow("Server URL/IP:", self.url_input)

        self.preset_combo = QComboBox(self)
        self.preset_combo.addItems(list(settings.get("presets", {}).keys()))
        layout.addRow("Presets:", self.preset_combo)

        btn_save_preset = QPushButton("Save as Preset", self)
        btn_save_preset.clicked.connect(self.save_preset)
        layout.addRow(btn_save_preset)

        btn_load_preset = QPushButton("Load Preset", self)
        btn_load_preset.clicked.connect(self.load_preset)
        layout.addRow(btn_load_preset)

        btn_ok = QPushButton("OK", self)
        btn_ok.clicked.connect(self.accept)
        layout.addRow(btn_ok)
        self.setLayout(layout)

    def save_preset(self):
        name, ok = QInputDialog.getText(self, "Preset Name", "Enter preset name:")
        if ok and name:
            self.settings.setdefault("presets", {})[name] = self.url_input.text()
            save_settings(self.settings)
            self.preset_combo.clear()
            self.preset_combo.addItems(list(self.settings["presets"].keys()))

    def load_preset(self):
        name = self.preset_combo.currentText()
        if name and name in self.settings.get("presets", {}):
            self.url_input.setText(self.settings["presets"][name])

    def get_url(self):
        return self.url_input.text().strip()

class FTPWebClient(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FTP Web Client (Python)")
        self.resize(900, 600)
        self.settings = load_settings()
        self.api_url = self.settings.get("last_url", "http://localhost:3000")
        self.token = None
        self.role = None
        self.cwd = ""
        self.files = []
        self.selected_file = None

        # Top bar
        top_bar = QHBoxLayout()
        self.lbl_user = QLabel("Not logged in")
        top_bar.addWidget(self.lbl_user)
        top_bar.addStretch()
        btn_settings = QPushButton("⚙️ Settings")
        btn_settings.clicked.connect(self.show_settings)
        top_bar.addWidget(btn_settings)

        # File list
        self.file_list = QListWidget()
        self.file_list.itemDoubleClicked.connect(self.on_item_double_clicked)
        self.file_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_list.customContextMenuRequested.connect(self.show_context_menu)

        # Toolbar
        toolbar = QHBoxLayout()
        btn_up = QPushButton("⬆ Up")
        btn_up.clicked.connect(self.go_up)
        btn_refresh = QPushButton("🔄 Refresh")
        btn_refresh.clicked.connect(self.refresh_files)
        btn_upload_file = QPushButton("⬆ Upload File(s)")
        btn_upload_file.clicked.connect(self.upload_files)
        btn_upload_folder = QPushButton("📁 Upload Folder")
        btn_upload_folder.clicked.connect(self.upload_folder)
        btn_new_folder = QPushButton("📁 New Folder")
        btn_new_folder.clicked.connect(self.create_folder)
        btn_new_file = QPushButton("📄 New File")
        btn_new_file.clicked.connect(self.create_file)
        toolbar.addWidget(btn_up)
        toolbar.addWidget(btn_refresh)
        toolbar.addWidget(btn_upload_file)
        toolbar.addWidget(btn_upload_folder)
        toolbar.addWidget(btn_new_folder)
        toolbar.addWidget(btn_new_file)
        toolbar.addStretch()

        # Quota bar
        self.quota_label = QLabel("Storage: ...")
        self.quota_bar = QProgressBar()
        self.quota_bar.setMaximum(100)
        quota_layout = QHBoxLayout()
        quota_layout.addWidget(self.quota_label)
        quota_layout.addWidget(self.quota_bar)

        # Main layout
        main_layout = QVBoxLayout()
        main_layout.addLayout(top_bar)
        main_layout.addLayout(toolbar)
        main_layout.addLayout(quota_layout)
        main_layout.addWidget(self.file_list)

        # Central widget
        central = QWidget()
        central.setLayout(main_layout)
        self.setCentralWidget(central)

        # Timer for quota polling
        self.quota_timer = QTimer(self)
        self.quota_timer.timeout.connect(self.fetch_quota)

        self.show_login()

    def api(self, path, method="GET", data=None, files=None):
        url = self.api_url.rstrip("/") + path
        headers = {}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        try:
            if method == "GET":
                resp = requests.get(url, headers=headers)
            elif method == "POST":
                resp = requests.post(url, headers=headers, json=data)
            elif method == "DELETE":
                resp = requests.delete(url, headers=headers, json=data)
            else:
                return None
            if resp.status_code == 200:
                return resp.json()
            else:
                QMessageBox.warning(self, "API Error", f"{resp.status_code}: {resp.text}")
                return None
        except Exception as e:
            QMessageBox.warning(self, "Network Error", str(e))
            return None

    def show_login(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Login")
        layout = QFormLayout()
        username_input = QLineEdit()
        password_input = QLineEdit()
        password_input.setEchoMode(QLineEdit.Password)
        layout.addRow("Username:", username_input)
        layout.addRow("Password:", password_input)
        btn_login = QPushButton("Login")
        layout.addRow(btn_login)
        dlg.setLayout(layout)
        btn_login.clicked.connect(dlg.accept)
        if dlg.exec_():
            username = username_input.text().strip()
            password = password_input.text()
            data = self.api("/api/login", "POST", {"username": username, "password": password})
            if data and "token" in data:
                self.token = data["token"]
                self.role = data.get("role")
                self.lbl_user.setText(f"Logged in as {username} ({self.role})")
                self.refresh_files()
                self.fetch_quota()
                self.quota_timer.start(5000)
            else:
                self.show_login()

    def refresh_files(self):
        data = self.api(f"/api/files?path={self.cwd}")
        if data is not None:
            self.files = data
            self.file_list.clear()
            for f in self.files:
                item = QListWidgetItem(("📁 " if f["isDir"] else "📄 ") + f["name"])
                item.setData(Qt.UserRole, f)
                self.file_list.addItem(item)

    def fetch_quota(self):
        user = self.lbl_user.text().split()[2] if "as" in self.lbl_user.text() else ""
        data = self.api(f"/api/limit/{user}")
        if data:
            used = float(data.get("usedGB", 0))
            limit = float(data.get("limitGB", 0))
            percent = int((used / limit) * 100) if limit > 0 else 0
            self.quota_label.setText(f"Storage: {used:.2f} GB / {limit} GB")
            self.quota_bar.setValue(percent)

    def go_up(self):
        if not self.cwd:
            return
        self.cwd = "/".join(self.cwd.rstrip("/").split("/")[:-1])
        self.refresh_files()

    def on_item_double_clicked(self, item):
        f = item.data(Qt.UserRole)
        if f["isDir"]:
            self.cwd = (self.cwd + "/" + f["name"]).strip("/")
            self.refresh_files()
        else:
            self.download_file(f["name"])

    def show_context_menu(self, pos):
        item = self.file_list.itemAt(pos)
        if not item:
            return
        f = item.data(Qt.UserRole)
        menu = QMenu(self)
        if f["isDir"]:
            menu.addAction("Open", lambda: self.on_item_double_clicked(item))
        else:
            menu.addAction("Download", lambda: self.download_file(f["name"]))
        menu.addAction("Rename", lambda: self.rename_file(f["name"], f["isDir"]))
        menu.addAction("Delete", lambda: self.delete_file(f["name"]))
        menu.exec_(self.file_list.viewport().mapToGlobal(pos))

    def upload_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select file(s) to upload")
        if not files:
            return
        for file_path in files:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            filename = os.path.basename(file_path)
            upload_path = self.cwd + "/" + filename if self.cwd else filename
            self.api("/api/file", "POST", {"path": upload_path, "content": content})
        self.refresh_files()
        self.fetch_quota()

    def upload_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select folder to upload")
        if not folder:
            return
        for root, dirs, files in os.walk(folder):
            for file in files:
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, folder)
                upload_path = (self.cwd + "/" + rel_path).replace("\\", "/") if self.cwd else rel_path.replace("\\", "/")
                with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                self.api("/api/file", "POST", {"path": upload_path, "content": content})
        self.refresh_files()
        self.fetch_quota()

    def create_folder(self):
        name, ok = QInputDialog.getText(self, "New Folder", "Folder name:")
        if ok and name:
            upload_path = self.cwd + "/" + name if self.cwd else name
            self.api("/api/file", "POST", {"path": upload_path, "content": None})
            self.refresh_files()

    def create_file(self):
        name, ok = QInputDialog.getText(self, "New File", "File name:")
        if ok and name:
            upload_path = self.cwd + "/" + name if self.cwd else name
            self.api("/api/file", "POST", {"path": upload_path, "content": ""})
            self.refresh_files()

    def download_file(self, name):
        data = self.api(f"/api/file?path={self.cwd + '/' + name if self.cwd else name}")
        if data and "content" in data:
            save_path, _ = QFileDialog.getSaveFileName(self, "Save File", name)
            if save_path:
                with open(save_path, "w", encoding="utf-8", errors="ignore") as f:
                    f.write(data["content"])

    def rename_file(self, old_name, is_dir):
        new_name, ok = QInputDialog.getText(self, "Rename", "New name:", text=old_name)
        if ok and new_name and new_name != old_name:
            self.api("/api/file", "POST", {
                "path": self.cwd + "/" + old_name if self.cwd else old_name,
                "newName": new_name,
                "isDir": is_dir
            })
            self.refresh_files()

    def delete_file(self, name):
        if QMessageBox.question(self, "Delete", f"Delete {name}?") == QMessageBox.Yes:
            self.api("/api/file", "DELETE", {
                "path": self.cwd + "/" + name if self.cwd else name
            })
            self.refresh_files()
            self.fetch_quota()

    def show_settings(self):
        dlg = SettingsDialog(self, self.settings)
        if dlg.exec_():
            url = dlg.get_url()
            if url:
                self.api_url = url
                self.settings["last_url"] = url
                save_settings(self.settings)
                QMessageBox.information(self, "Settings", "Server URL updated. Please login again.")
                self.token = None
                self.role = None
                self.lbl_user.setText("Not logged in")
                self.show_login()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = FTPWebClient()
    win.show()
    sys.exit(app.exec_())
