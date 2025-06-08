import re
import sys
import os
import json
import secrets
import string
import hashlib
import base64
import sqlite3
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from cryptography.fernet import Fernet
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QListWidget, QListWidgetItem, QMessageBox, QDialog,
    QCheckBox, QSpinBox, QTextEdit, QGroupBox, QInputDialog, QComboBox, QFrame, QStackedWidget, QFormLayout
)
from PyQt6.QtGui import (
    QIcon, QPixmap, QFont, QPalette, QBrush, QColor, QLinearGradient, QPainter, QImage
)
from PyQt6.QtCore import Qt, QSize, QTimer, QRectF, QPropertyAnimation, QEasingCurve

# Configuration du logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("password_manager.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("PasswordManager")

# Paramètres de l'application
APP_NAME = "SecurePass Manager"
VERSION = "2.0"
MASTER_KEY_FILE = "securepass.key"
DATABASE_FILE = "securepass.db"
BACKGROUND_IMAGE = "background.jpg"  # Remplacez par votre image

class PasswordGenerator:
    """Générateur de mots de passe cryptographiquement forts avec analyse de sécurité"""
    AMBIGUOUS_CHARS = 'l1IoO0'
    SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    def __init__(self):
        self.entropy_cache = {}

    def generate_password(
        self,
        length: int = 16,
        use_lowercase: bool = True,
        use_uppercase: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
        exclude_ambiguous: bool = True,
        exclude_chars: str = '',
        min_entropy: float = 80.0
    ) -> str:
        """Génère un mot de passe selon les critères spécifiés avec vérification d'entropie"""
        charset = ''
        if use_lowercase:
            charset += string.ascii_lowercase
        if use_uppercase:
            charset += string.ascii_uppercase
        if use_digits:
            charset += string.digits
        if use_symbols:
            charset += self.SYMBOLS
        
        if not charset:
            raise ValueError("Au moins un jeu de caractères doit être sélectionné")
        
        if exclude_ambiguous:
            charset = ''.join(c for c in charset if c not in self.AMBIGUOUS_CHARS)
        
        if exclude_chars:
            charset = ''.join(c for c in charset if c not in exclude_chars)
        
        # Génération avec vérification d'entropie
        for _ in range(100):  # 100 tentatives max
            password = ''.join(secrets.choice(charset) for _ in range(length))
            entropy = self.calculate_entropy(password, charset)
            
            if entropy >= min_entropy:
                logger.info(f"Password generated with entropy: {entropy:.2f} bits")
                return password
        
        raise RuntimeError("Impossible de générer un mot de passe avec l'entropie requise")

    def calculate_entropy(self, password: str, charset: str) -> float:
        """Calcule l'entropie du mot de passe en bits"""
        if password in self.entropy_cache:
            return self.entropy_cache[password]
        
        charset_size = len(charset)
        entropy = len(password) * (hashlib.sha256(password.encode()).digest()[0] / 32) * charset_size
        
        # Vérification des motifs communs
        patterns = [
            (r'(.)\1{2,}', 0.5),  # Répétitions
            (r'123|abc|qwerty', 0.3),  # Séquences communes
            (r'\d{4,}', 0.7),  # Longs chiffres
        ]
        
        for pattern, penalty in patterns:
            if re.search(pattern, password, re.IGNORECASE):
                entropy *= penalty
        
        self.entropy_cache[password] = entropy
        return entropy

class PasswordManager:
    """Gestionnaire sécurisé de mots de passe avec audit de sécurité"""
    def __init__(self, db_path: str = DATABASE_FILE):
        self.db_path = db_path
        self.key = None
        self.key_salt = None
        self._init_db()
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Dérive une clé à partir du mot de passe maître avec KDF"""
        return base64.urlsafe_b64encode(
            hashlib.pbkdf2_hmac(
                'sha512', 
                password.encode(), 
                salt, 
                310000,  # OWASP recommandation 2023
                32
            )
        )
    
    def _load_or_create_key(self) -> tuple[bytes, bytes]:
        """Charge ou crée la clé maître avec authentification"""
        if os.path.exists(MASTER_KEY_FILE):
            with open(MASTER_KEY_FILE, "rb") as f:
                data = f.read()
                salt = data[:32]
                encrypted_key = data[32:-64]
                stored_hmac = data[-64:]
            
            password, ok = QInputDialog.getText(
                None, 
                "Authentification",
                "Mot de passe maître:",
                QLineEdit.EchoMode.Password
            )
            
            if not ok or not password:
                raise ValueError("Authentification annulée")
            
            derived_key = self._derive_key(password, salt)
            
            try:
                key = Fernet(derived_key).decrypt(encrypted_key)
                # Vérification d'authenticité
                if hashlib.blake2b(key).digest() != stored_hmac:
                    raise ValueError("Fichier corrompu ou altéré")
                return key, salt
            except:
                logger.error("Authentification échouée ou fichier corrompu")
                raise
        
        password, ok = QInputDialog.getText(
            None, 
            "Nouveau mot de passe maître",
            "Créez un mot de passe maître (min 12 caractères):",
            QLineEdit.EchoMode.Password
        )
        
        if not ok or not password:
            raise ValueError("Création annulée")
        
        if len(password) < 12:
            raise ValueError("Le mot de passe doit contenir au moins 12 caractères")
        
        verify, ok = QInputDialog.getText(
            None,
            "Confirmation",
            "Confirmez le mot de passe:",
            QLineEdit.EchoMode.Password
        )
        
        if not ok or password != verify:
            raise ValueError("Les mots de passe ne correspondent pas")
        
        salt = secrets.token_bytes(32)
        derived_key = self._derive_key(password, salt)
        key = Fernet.generate_key()
        
        # Ajout d'un HMAC pour vérification d'intégrité
        hmac = hashlib.blake2b(key).digest()
        encrypted_key = Fernet(derived_key).encrypt(key)
        
        with open(MASTER_KEY_FILE, "wb") as f:
            f.write(salt + encrypted_key + hmac)
        
        logger.info("Nouvelle clé maître créée avec succès")
        return key, salt

    def _init_db(self):
        """Initialise la base de données avec schéma sécurisé"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vault (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL UNIQUE,
                    username TEXT,
                    password TEXT NOT NULL,
                    metadata TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS update_timestamp
                AFTER UPDATE ON vault
                BEGIN
                    UPDATE vault SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
                END
            """)
    
    def _encrypt(self, data: str) -> str:
        """Chiffre une chaîne de caractères avec authentification"""
        return Fernet(self.key).encrypt(data.encode()).decode()
    
    def _decrypt(self, data: str) -> str:
        """Déchiffre une chaîne de caractères avec vérification d'intégrité"""
        return Fernet(self.key).decrypt(data.encode()).decode()
    
    def authenticate(self):
        """Authentifie l'utilisateur"""
        try:
            self.key, self.key_salt = self._load_or_create_key()
            return True
        except Exception as e:
            logger.error(f"Erreur d'authentification: {str(e)}")
            QMessageBox.critical(None, "Erreur", f"Erreur d'authentification: {str(e)}")
            return False
    
    def add_password(
        self, 
        service: str, 
        username: str, 
        password: str, 
        metadata: Optional[Dict] = None
    ):
        """Ajoute une entrée au coffre-fort avec horodatage"""
        encrypted_password = self._encrypt(password)
        encrypted_metadata = self._encrypt(json.dumps(metadata or {}))
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO vault (service, username, password, metadata)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(service) DO UPDATE SET
                username = excluded.username,
                password = excluded.password,
                metadata = excluded.metadata
            """, (service, username, encrypted_password, encrypted_metadata))
        logger.info(f"Entrée '{service}' mise à jour")
    
    def get_password(self, service: str) -> Optional[Dict]:
        """Récupère un mot de passe par service avec vérification"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute("""
                SELECT username, password, metadata, created_at, updated_at
                FROM vault
                WHERE service = ?
            """, (service,))
            result = cur.fetchone()
        
        if not result:
            return None
        
        try:
            return {
                'username': result['username'],
                'password': self._decrypt(result['password']),
                'metadata': json.loads(self._decrypt(result['metadata'])),
                'created_at': result['created_at'],
                'updated_at': result['updated_at']
            }
        except:
            logger.error("Échec du déchiffrement - possible altération des données")
            return None
    
    def delete_password(self, service: str) -> bool:
        """Supprime une entrée du coffre-fort"""
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("DELETE FROM vault WHERE service = ?", (service,))
            if cur.rowcount > 0:
                logger.info(f"Entrée '{service}' supprimée")
                return True
        return False
    
    def list_services(self) -> List[Dict]:
        """Liste tous les services enregistrés avec dates"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute("SELECT service, created_at, updated_at FROM vault ORDER BY service")
            return [
                {
                    'service': row['service'],
                    'created_at': row['created_at'],
                    'updated_at': row['updated_at']
                } for row in cur.fetchall()
            ]
    
    def security_audit(self) -> Dict[str, Any]:
        """Effectue un audit de sécurité du coffre-fort"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute("SELECT COUNT(*) as count FROM vault")
            total_entries = cur.fetchone()['count']
            
            cur = conn.execute("""
                SELECT service, password FROM vault
            """)
            
            weak_passwords = []
            reused_passwords = {}
            password_counter = {}
            
            for row in cur.fetchall():
                try:
                    password = self._decrypt(row['password'])
                    
                    # Détection de réutilisation
                    password_counter[password] = password_counter.get(password, 0) + 1
                    
                    # Analyse de sécurité
                    entropy = PasswordGenerator().calculate_entropy(
                        password,
                        string.ascii_letters + string.digits + PasswordGenerator.SYMBOLS
                    )
                    
                    if entropy < 70:
                        weak_passwords.append({
                            'service': row['service'],
                            'entropy': entropy
                        })
                
                except:
                    continue
            
            # Compter les réutilisations
            for password, count in password_counter.items():
                if count > 1:
                    reused_passwords[password] = count
            
            return {
                'total_entries': total_entries,
                'weak_passwords': weak_passwords,
                'reused_passwords': reused_passwords,
                'last_audit': datetime.now().isoformat()
            }

class GradientWidget(QWidget):
    """Widget avec fond en dégradé"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(800, 600)
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Dégradé de fond
        gradient = QLinearGradient(0, 0, self.width(), self.height())
        gradient.setColorAt(0.0, QColor(30, 30, 50))
        gradient.setColorAt(1.0, QColor(10, 10, 30))
        
        painter.fillRect(self.rect(), gradient)
        
        # Ajouter des effets visuels
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(255, 255, 255, 20))
        for _ in range(5):
            x = secrets.randbelow(self.width())
            y = secrets.randbelow(self.height())
            size = secrets.randbelow(100) + 50
            painter.drawEllipse(x, y, size, size)

class ImageBackgroundWidget(QWidget):
    """Widget avec image de fond"""
    def __init__(self, image_path, parent=None):
        super().__init__(parent)
        self.image_path = image_path
        self.overlay_color = QColor(0, 0, 0, 180)  # Overlay semi-transparent
        
    def paintEvent(self, event):
        painter = QPainter(self)
        
        # Charger l'image de fond
        if os.path.exists(self.image_path):
            pixmap = QPixmap(self.image_path)
            painter.drawPixmap(self.rect(), pixmap.scaled(
                self.size(), 
                Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation
            ))
        
        # Overlay semi-transparent
        painter.fillRect(self.rect(), self.overlay_color)
        
        # Ajouter un effet de particules
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(255, 255, 255, 30))
        for _ in range(20):
            x = secrets.randbelow(self.width())
            y = secrets.randbelow(self.height())
            size = secrets.randbelow(5) + 2
            painter.drawEllipse(x, y, size, size)

class AuthWindow(QDialog):
    """Fenêtre d'authentification"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Authentification")
        self.setFixedSize(500, 350)
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        
        # Layout principal
        layout = QVBoxLayout()
        layout.setContentsMargins(50, 50, 50, 50)
        
        # Conteneur
        container = QWidget()
        container.setStyleSheet("""
            background-color: rgba(30, 30, 50, 200);
            border-radius: 15px;
            border: 1px solid #4a4a6a;
        """)
        
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(30, 30, 30, 30)
        container_layout.setSpacing(20)
        
        # Titre
        title = QLabel("SecurePass Manager")
        title.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #ffffff;
            margin-bottom: 20px;
        """)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Champ mot de passe
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("Mot de passe maître")
        self.password_edit.setStyleSheet("""
            background-color: rgba(50, 50, 70, 150);
            color: white;
            border: 1px solid #5a5a8a;
            border-radius: 5px;
            padding: 10px;
            font-size: 16px;
        """)
        
        # Bouton d'authentification
        auth_button = QPushButton("S'authentifier")
        auth_button.setStyleSheet("""
            QPushButton {
                background-color: #5c6bc0;
                color: white;
                border-radius: 5px;
                padding: 12px;
                font-size: 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3f51b5;
            }
        """)
        auth_button.clicked.connect(self.authenticate)
        
        # Message d'erreur
        self.error_label = QLabel()
        self.error_label.setStyleSheet("color: #ff6b6b;")
        self.error_label.setVisible(False)
        self.error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Ajout au layout
        container_layout.addWidget(title)
        container_layout.addWidget(self.password_edit)
        container_layout.addWidget(auth_button)
        container_layout.addWidget(self.error_label)
        
        layout.addWidget(container)
        self.setLayout(layout)
        
        # Animation d'apparition
        self.animation = QPropertyAnimation(self, b"windowOpacity")
        self.animation.setDuration(500)
        self.animation.setStartValue(0)
        self.animation.setEndValue(1)
        self.animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.animation.start()
    
    def authenticate(self):
        password = self.password_edit.text()
        if not password:
            self.error_label.setText("Veuillez entrer un mot de passe")
            self.error_label.setVisible(True)
            return
        
        # Ici vous intégreriez la logique d'authentification réelle
        # Pour l'exemple, on accepte n'importe quel mot de passe
        self.accept()

class MainWindow(QMainWindow):
    """Fenêtre principale de l'application"""
    def __init__(self, manager):
        super().__init__()
        self.manager = manager
        self.generator = PasswordGenerator()
        self.setWindowTitle(f"{APP_NAME} v{VERSION}")
        self.setMinimumSize(1000, 700)
        
        # Configuration du style
        self.setStyle()
        
        # Création du widget central avec fond
        self.central_widget = ImageBackgroundWidget(BACKGROUND_IMAGE)
        self.setCentralWidget(self.central_widget)
        
        # Layout principal
        main_layout = QVBoxLayout(self.central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        
        # Barre de titre personnalisée
        self.create_title_bar()
        main_layout.addWidget(self.title_bar)
        
        # Création de l'interface à onglets
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                background: rgba(40, 40, 60, 180);
                border-radius: 10px;
            }
            QTabBar::tab {
                background: rgba(50, 50, 80, 200);
                color: white;
                padding: 10px 20px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: rgba(92, 107, 192, 200);
            }
        """)
        
        # Création des onglets
        self.create_home_tab()
        self.create_generator_tab()
        self.create_vault_tab()
        self.create_audit_tab()
        
        main_layout.addWidget(self.tab_widget)
        
        # Barre de statut
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Prêt")
    
    def setStyle(self):
        """Configure le style global de l'application"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1a1a2e;
            }
            QLabel {
                color: #ffffff;
            }
            QPushButton {
                background-color: #5c6bc0;
                color: white;
                border-radius: 5px;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: #3f51b5;
            }
            QListWidget {
                background-color: rgba(50, 50, 70, 150);
                color: white;
                border: 1px solid #5a5a8a;
                border-radius: 5px;
            }
            QLineEdit, QSpinBox, QComboBox, QTextEdit {
                background-color: rgba(50, 50, 70, 150);
                color: white;
                border: 1px solid #5a5a8a;
                border-radius: 5px;
                padding: 5px;
            }
            QGroupBox {
                font-weight: bold;
                color: #ffffff;
                border: 1px solid #5a5a8a;
                border-radius: 5px;
                margin-top: 20px;
                padding: 10px;
            }
        """)
    
    def create_title_bar(self):
        """Crée une barre de titre personnalisée"""
        self.title_bar = QWidget()
        self.title_bar.setStyleSheet("background: transparent;")
        title_layout = QHBoxLayout(self.title_bar)
        title_layout.setContentsMargins(0, 0, 0, 0)
        
        # Logo et titre
        logo = QLabel()
        logo.setPixmap(QIcon("icon.png").pixmap(32, 32))  # Remplacez par votre logo
        title = QLabel(APP_NAME)
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: white;")
        
        # Boutons de contrôle
        btn_minimize = QPushButton("—")
        btn_minimize.setFixedSize(30, 30)
        btn_minimize.clicked.connect(self.showMinimized)
        
        btn_close = QPushButton("✕")
        btn_close.setFixedSize(30, 30)
        btn_close.clicked.connect(self.close)
        
        title_layout.addWidget(logo)
        title_layout.addWidget(title)
        title_layout.addStretch()
        title_layout.addWidget(btn_minimize)
        title_layout.addWidget(btn_close)
    
    def create_home_tab(self):
        """Crée l'onglet d'accueil"""
        home_tab = QWidget()
        layout = QVBoxLayout(home_tab)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Message de bienvenue
        welcome = QLabel("Bienvenue dans SecurePass Manager")
        welcome.setStyleSheet("font-size: 24px; font-weight: bold; color: white;")
        welcome.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Description
        description = QLabel(
            "Votre solution sécurisée pour gérer tous vos mots de passe\n"
            "et générer des identifiants forts et uniques."
        )
        description.setStyleSheet("font-size: 16px; color: #cccccc;")
        description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Statistiques
        stats_group = QGroupBox("Statistiques")
        stats_layout = QGridLayout()
        
        total_label = QLabel("Total des entrées:")
        self.total_value = QLabel("0")
        self.total_value.setStyleSheet("font-size: 18px; font-weight: bold;")
        
        weak_label = QLabel("Mots de passe faibles:")
        self.weak_value = QLabel("0")
        self.weak_value.setStyleSheet("font-size: 18px; font-weight: bold; color: #ff6b6b;")
        
        reused_label = QLabel("Mots de passe réutilisés:")
        self.reused_value = QLabel("0")
        self.reused_value.setStyleSheet("font-size: 18px; font-weight: bold; color: #ff6b6b;")
        
        stats_layout.addWidget(total_label, 0, 0)
        stats_layout.addWidget(self.total_value, 0, 1)
        stats_layout.addWidget(weak_label, 1, 0)
        stats_layout.addWidget(self.weak_value, 1, 1)
        stats_layout.addWidget(reused_label, 2, 0)
        stats_layout.addWidget(self.reused_value, 2, 1)
        stats_group.setLayout(stats_layout)
        
        # Boutons d'action
        btn_layout = QHBoxLayout()
        btn_add = QPushButton("Ajouter un mot de passe")
        btn_add.setIcon(QIcon("add.png"))
        btn_add.setMinimumHeight(40)
        btn_add.clicked.connect(lambda: self.tab_widget.setCurrentIndex(2))
        
        btn_generate = QPushButton("Générer un mot de passe")
        btn_generate.setIcon(QIcon("generate.png"))
        btn_generate.setMinimumHeight(40)
        btn_generate.clicked.connect(lambda: self.tab_widget.setCurrentIndex(1))
        
        btn_layout.addWidget(btn_add)
        btn_layout.addWidget(btn_generate)
        
        layout.addStretch()
        layout.addWidget(welcome)
        layout.addWidget(description)
        layout.addSpacing(30)
        layout.addWidget(stats_group)
        layout.addSpacing(20)
        layout.addLayout(btn_layout)
        layout.addStretch()
        
        self.tab_widget.addTab(home_tab, QIcon("home.png"), "Accueil")
    
    def create_generator_tab(self):
        """Crée l'onglet générateur de mots de passe"""
        generator_tab = QWidget()
        layout = QVBoxLayout(generator_tab)
        
        # Configuration du générateur
        config_group = QGroupBox("Configuration du mot de passe")
        config_layout = QGridLayout()
        
        config_layout.addWidget(QLabel("Longueur:"), 0, 0)
        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 64)
        self.length_spin.setValue(16)
        config_layout.addWidget(self.length_spin, 0, 1)
        
        self.lower_check = QCheckBox("Inclure des minuscules")
        self.lower_check.setChecked(True)
        config_layout.addWidget(self.lower_check, 1, 0)
        
        self.upper_check = QCheckBox("Inclure des majuscules")
        self.upper_check.setChecked(True)
        config_layout.addWidget(self.upper_check, 1, 1)
        
        self.digits_check = QCheckBox("Inclure des chiffres")
        self.digits_check.setChecked(True)
        config_layout.addWidget(self.digits_check, 2, 0)
        
        self.symbols_check = QCheckBox("Inclure des symboles")
        self.symbols_check.setChecked(True)
        config_layout.addWidget(self.symbols_check, 2, 1)
        
        self.ambiguous_check = QCheckBox("Exclure les caractères ambigus (l,1,I,O,0)")
        self.ambiguous_check.setChecked(True)
        config_layout.addWidget(self.ambiguous_check, 3, 0, 1, 2)
        
        config_group.setLayout(config_layout)
        
        # Bouton de génération
        self.generate_btn = QPushButton("Générer un mot de passe")
        self.generate_btn.setIcon(QIcon("refresh.png"))
        self.generate_btn.setMinimumHeight(40)
        self.generate_btn.clicked.connect(self.generate_password)
        
        # Résultat
        result_group = QGroupBox("Résultat")
        result_layout = QVBoxLayout()
        
        self.password_result = QLineEdit()
        self.password_result.setReadOnly(True)
        self.password_result.setStyleSheet("font-size: 18px; font-weight: bold;")
        
        self.entropy_label = QLabel("Entropie: -")
        self.entropy_label.setStyleSheet("font-size: 14px; color: #cccccc;")
        
        btn_layout = QHBoxLayout()
        self.copy_btn = QPushButton("Copier")
        self.copy_btn.setIcon(QIcon("copy.png"))
        self.copy_btn.clicked.connect(self.copy_password)
        
        self.save_btn = QPushButton("Enregistrer")
        self.save_btn.setIcon(QIcon("save.png"))
        self.save_btn.clicked.connect(self.save_generated_password)
        
        btn_layout.addWidget(self.copy_btn)
        btn_layout.addWidget(self.save_btn)
        
        result_layout.addWidget(self.password_result)
        result_layout.addWidget(self.entropy_label)
        result_layout.addLayout(btn_layout)
        result_group.setLayout(result_layout)
        
        layout.addWidget(config_group)
        layout.addWidget(self.generate_btn)
        layout.addWidget(result_group)
        layout.addStretch()
        
        self.tab_widget.addTab(generator_tab, QIcon("key.png"), "Générateur")
    
    def create_vault_tab(self):
        """Crée l'onglet coffre-fort"""
        vault_tab = QWidget()
        layout = QVBoxLayout(vault_tab)
        
        # Barre de recherche
        search_layout = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Rechercher un service...")
        self.search_edit.textChanged.connect(self.filter_vault)
        
        self.add_btn = QPushButton("Ajouter")
        self.add_btn.setIcon(QIcon("add.png"))
        self.add_btn.clicked.connect(self.add_password)
        
        search_layout.addWidget(self.search_edit)
        search_layout.addWidget(self.add_btn)
        
        # Liste des mots de passe
        self.vault_list = QListWidget()
        self.vault_list.itemDoubleClicked.connect(self.show_password_details)
        
        layout.addLayout(search_layout)
        layout.addWidget(self.vault_list)
        
        self.tab_widget.addTab(vault_tab, QIcon("vault.png"), "Coffre-fort")
    
    def create_audit_tab(self):
        """Crée l'onglet d'audit de sécurité"""
        audit_tab = QWidget()
        layout = QVBoxLayout(audit_tab)
        
        # Bouton d'audit
        self.audit_btn = QPushButton("Lancer l'audit de sécurité")
        self.audit_btn.setIcon(QIcon("audit.png"))
        self.audit_btn.setMinimumHeight(40)
        self.audit_btn.clicked.connect(self.run_security_audit)
        
        # Résultats de l'audit
        self.audit_result = QTextEdit()
        self.audit_result.setReadOnly(True)
        
        layout.addWidget(self.audit_btn)
        layout.addWidget(self.audit_result)
        
        self.tab_widget.addTab(audit_tab, QIcon("shield.png"), "Audit")
    
    def generate_password(self):
        """Génère un mot de passe selon les paramètres"""
        try:
            password = self.generator.generate_password(
                length=self.length_spin.value(),
                use_lowercase=self.lower_check.isChecked(),
                use_uppercase=self.upper_check.isChecked(),
                use_digits=self.digits_check.isChecked(),
                use_symbols=self.symbols_check.isChecked(),
                exclude_ambiguous=self.ambiguous_check.isChecked()
            )
            
            self.password_result.setText(password)
            
            # Calcul de l'entropie
            charset = ''
            if self.lower_check.isChecked():
                charset += string.ascii_lowercase
            if self.upper_check.isChecked():
                charset += string.ascii_uppercase
            if self.digits_check.isChecked():
                charset += string.digits
            if self.symbols_check.isChecked():
                charset += PasswordGenerator.SYMBOLS
            
            entropy = self.generator.calculate_entropy(password, charset)
            self.entropy_label.setText(f"Entropie: {entropy:.2f} bits - Combinaisons: 2^{entropy:.0f} ≈ {2**entropy:.1e}")
            
            # Couleur en fonction de la force
            if entropy < 70:
                self.entropy_label.setStyleSheet("color: #ff6b6b;")
            elif entropy < 90:
                self.entropy_label.setStyleSheet("color: #ffd166;")
            else:
                self.entropy_label.setStyleSheet("color: #06d6a0;")
                
        except Exception as e:
            QMessageBox.critical(self, "Erreur", str(e))
    
    def copy_password(self):
        """Copie le mot de passe dans le presse-papiers"""
        password = self.password_result.text()
        if password:
            clipboard = QApplication.clipboard()
            clipboard.setText(password)
            self.status_bar.showMessage("Mot de passe copié dans le presse-papiers", 3000)
    
    def save_generated_password(self):
        """Enregistre le mot de passe généré dans le coffre-fort"""
        password = self.password_result.text()
        if not password:
            QMessageBox.warning(self, "Erreur", "Aucun mot de passe à enregistrer")
            return
        
        service, ok = QInputDialog.getText(
            self, 
            "Enregistrer le mot de passe",
            "Service:"
        )
        
        if not ok or not service:
            return
        
        username, ok = QInputDialog.getText(
            self,
            "Nom d'utilisateur",
            f"Nom d'utilisateur pour {service}:"
        )
        
        if not ok:
            return
        
        try:
            self.manager.add_password(service, username, password)
            self.status_bar.showMessage(f"Mot de passe pour {service} enregistré", 3000)
            self.refresh_vault_list()
        except Exception as e:
            QMessageBox.critical(self, "Erreur", str(e))
    
    def filter_vault(self):
        """Filtre la liste des mots de passe"""
        search_text = self.search_edit.text().lower()
        self.vault_list.clear()
        
        services = self.manager.list_services()
        for service in services:
            if search_text in service['service'].lower():
                item = QListWidgetItem(service['service'])
                item.setData(Qt.ItemDataRole.UserRole, service)
                self.vault_list.addItem(item)
    
    def refresh_vault_list(self):
        """Rafraîchit la liste des mots de passe"""
        self.search_edit.clear()
        self.vault_list.clear()
        
        services = self.manager.list_services()
        for service in services:
            item = QListWidgetItem(service['service'])
            item.setData(Qt.ItemDataRole.UserRole, service)
            self.vault_list.addItem(item)
    
    def show_password_details(self, item):
        """Affiche les détails d'un mot de passe"""
        service_data = item.data(Qt.ItemDataRole.UserRole)
        service = service_data['service']
        
        entry = self.manager.get_password(service)
        if not entry:
            QMessageBox.warning(self, "Erreur", "Impossible de récupérer les détails du mot de passe")
            return
        
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Détails: {service}")
        dialog.setFixedSize(500, 400)
        
        layout = QVBoxLayout()
        
        # Formulaire de détails
        form = QFormLayout()
        
        service_edit = QLineEdit(service)
        service_edit.setReadOnly(True)
        
        user_edit = QLineEdit(entry['username'])
        user_edit.setReadOnly(True)
        
        password_edit = QLineEdit(entry['password'])
        password_edit.setReadOnly(True)
        password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        
        created_label = QLabel(entry['created_at'])
        updated_label = QLabel(entry['updated_at'])
        
        form.addRow("Service:", service_edit)
        form.addRow("Utilisateur:", user_edit)
        form.addRow("Mot de passe:", password_edit)
        form.addRow("Créé le:", created_label)
        form.addRow("Mis à jour le:", updated_label)
        
        # Boutons d'action
        btn_layout = QHBoxLayout()
        copy_btn = QPushButton("Copier le mot de passe")
        copy_btn.setIcon(QIcon("copy.png"))
        copy_btn.clicked.connect(lambda: self.copy_to_clipboard(entry['password']))
        
        delete_btn = QPushButton("Supprimer")
        delete_btn.setIcon(QIcon("delete.png"))
        delete_btn.setStyleSheet("background-color: #e74c3c;")
        delete_btn.clicked.connect(lambda: self.delete_password(service, dialog))
        
        btn_layout.addWidget(copy_btn)
        btn_layout.addWidget(delete_btn)
        
        layout.addLayout(form)
        layout.addLayout(btn_layout)
        dialog.setLayout(layout)
        dialog.exec()
    
    def copy_to_clipboard(self, text):
        """Copie du texte dans le presse-papiers"""
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        self.status_bar.showMessage("Copié dans le presse-papiers", 3000)
    
    def delete_password(self, service, dialog):
        """Supprime un mot de passe du coffre-fort"""
        reply = QMessageBox.question(
            self,
            "Confirmation",
            f"Êtes-vous sûr de vouloir supprimer le mot de passe pour {service}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            if self.manager.delete_password(service):
                self.status_bar.showMessage(f"Mot de passe pour {service} supprimé", 3000)
                self.refresh_vault_list()
                dialog.accept()
            else:
                QMessageBox.warning(self, "Erreur", "Échec de la suppression")
    
    def run_security_audit(self):
        """Exécute un audit de sécurité"""
        self.audit_result.clear()
        self.audit_result.append("⏳ Exécution de l'audit de sécurité...")
        QApplication.processEvents()  # Mettre à jour l'interface
        
        try:
            audit = self.manager.security_audit()
            
            report = f"🔒 <b>Audit de sécurité - {audit['last_audit']}</b><br>"
            report += f"📊 <b>Entrées totales:</b> {audit['total_entries']}<br><br>"
            
            if audit['weak_passwords']:
                report += "⚠️ <b>Mots de passe faibles détectés:</b><br>"
                for item in audit['weak_passwords']:
                    report += f"- {item['service']} (entropie: {item['entropy']:.1f} bits)<br>"
            else:
                report += "✅ <b>Aucun mot de passe faible détecté</b><br>"
            
            report += "<br>"
            
            if audit['reused_passwords']:
                report += "⚠️ <b>Mots de passe réutilisés:</b><br>"
                for pwd, count in audit['reused_passwords'].items():
                    report += f"- Mot de passe utilisé {count} fois<br>"
            else:
                report += "✅ <b>Aucune réutilisation de mot de passe détectée</b><br>"
            
            self.audit_result.setHtml(report)
            
            # Mettre à jour les statistiques sur l'onglet d'accueil
            self.total_value.setText(str(audit['total_entries']))
            self.weak_value.setText(str(len(audit['weak_passwords'])))
            self.reused_value.setText(str(len(audit['reused_passwords'])))
            
        except Exception as e:
            self.audit_result.append(f"❌ Erreur lors de l'audit: {str(e)}")
    
    def add_password(self):
        """Ajoute un nouveau mot de passe au coffre-fort"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Ajouter un mot de passe")
        dialog.setFixedSize(500, 400)
        
        layout = QVBoxLayout()
        
        # Formulaire
        form = QFormLayout()
        
        service_edit = QLineEdit()
        service_edit.setPlaceholderText("Ex: Google, Facebook")
        
        user_edit = QLineEdit()
        user_edit.setPlaceholderText("Ex: john.doe@example.com")
        
        password_edit = QLineEdit()
        password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        password_edit.setPlaceholderText("Mot de passe")
        
        generate_btn = QPushButton("Générer un mot de passe")
        generate_btn.clicked.connect(lambda: self.open_generator_tab(dialog))
        
        form.addRow("Service:", service_edit)
        form.addRow("Nom d'utilisateur:", user_edit)
        form.addRow("Mot de passe:", password_edit)
        form.addRow(generate_btn)
        
        # Boutons
        btn_layout = QHBoxLayout()
        save_btn = QPushButton("Enregistrer")
        save_btn.clicked.connect(lambda: self.save_new_password(
            service_edit.text(), 
            user_edit.text(), 
            password_edit.text(),
            dialog
        ))
        
        cancel_btn = QPushButton("Annuler")
        cancel_btn.clicked.connect(dialog.reject)
        
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        
        layout.addLayout(form)
        layout.addLayout(btn_layout)
        dialog.setLayout(layout)
        dialog.exec()
    
    def save_new_password(self, service, username, password, dialog):
        """Enregistre un nouveau mot de passe"""
        if not service or not password:
            QMessageBox.warning(self, "Erreur", "Le service et le mot de passe sont obligatoires")
            return
        
        try:
            self.manager.add_password(service, username, password)
            self.status_bar.showMessage(f"Mot de passe pour {service} enregistré", 3000)
            self.refresh_vault_list()
            dialog.accept()
        except Exception as e:
            QMessageBox.critical(self, "Erreur", str(e))
    
    def open_generator_tab(self, dialog):
        """Ouvre l'onglet générateur"""
        self.tab_widget.setCurrentIndex(1)
        dialog.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Initialisation du gestionnaire
    manager = PasswordManager()
    
    # Authentification
    if manager.authenticate():
        window = MainWindow(manager)
        window.show()
        sys.exit(app.exec())
    else:
        sys.exit(1)