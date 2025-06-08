#!/usr/bin/env python3
import argparse
import sys
import secrets
import string
import sqlite3
import hashlib
import os
import json
from cryptography.fernet import Fernet
import base64
from getpass import getpass
from typing import Dict, Optional, List, Tuple, Any
import re
from datetime import datetime

# Configuration
DATABASE = "passwords.db"
MASTER_KEY_FILE = "master.key"
DEFAULT_LENGTH = 16
DEFAULT_MIN_ENTROPY = 80.0

class PasswordGenerator:
    """Générateur de mots de passe cryptographiquement forts"""
    AMBIGUOUS_CHARS = 'l1IoO0'
    SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    def generate_password(
        self,
        length: int = DEFAULT_LENGTH,
        use_lowercase: bool = True,
        use_uppercase: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
        exclude_ambiguous: bool = True,
        exclude_chars: str = '',
        min_entropy: float = DEFAULT_MIN_ENTROPY
    ) -> str:
        """Génère un mot de passe sécurisé"""
        charset = self._build_charset(
            use_lowercase, use_uppercase, use_digits, use_symbols,
            exclude_ambiguous, exclude_chars
        )
        
        for _ in range(100):
            password = ''.join(secrets.choice(charset) for _ in range(length))
            entropy = self.calculate_entropy(password, charset)
            if entropy >= min_entropy:
                return password
        raise RuntimeError("Impossible de générer un mot de passe avec les critères demandés")

    def _build_charset(self, *args) -> str:
        """Construit le jeu de caractères"""
        charset = ''
        if args[0]: charset += string.ascii_lowercase
        if args[1]: charset += string.ascii_uppercase
        if args[2]: charset += string.digits
        if args[3]: charset += self.SYMBOLS
        
        if not charset:
            raise ValueError("Au moins un jeu de caractères doit être sélectionné")
        
        if args[4]:  # exclude_ambiguous
            charset = ''.join(c for c in charset if c not in self.AMBIGUOUS_CHARS)
        
        if args[5]:  # exclude_chars
            charset = ''.join(c for c in charset if c not in args[5])
        
        return charset

    def calculate_entropy(self, password: str, charset: str) -> float:
        """Calcule l'entropie en bits"""
        charset_size = len(charset)
        entropy = len(password) * (hashlib.sha256(password.encode()).digest()[0] / 32) * charset_size
        
        # Pénalités pour motifs faibles
        weak_patterns = [
            (r'(.)\1{2,}', 0.5),  # Répétitions
            (r'123|abc|qwerty', 0.3),  # Séquences
            (r'\d{4,}', 0.7)  # Chiffres consécutifs
        ]
        
        for pattern, penalty in weak_patterns:
            if re.search(pattern, password, re.IGNORECASE):
                entropy *= penalty
                
        return entropy

class PasswordManager:
    """Gestionnaire sécurisé de mots de passe"""
    def __init__(self, db_path: str = DATABASE):
        self.db_path = db_path
        self.key = None
        self._init_db()
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Dérive une clé de chiffrement"""
        return base64.urlsafe_b64encode(
            hashlib.pbkdf2_hmac('sha512', password.encode(), salt, 310000, 32)
        )
    
    def _init_db(self):
        """Initialise la base de données"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vault (
                    id INTEGER PRIMARY KEY,
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
        """Chiffre les données"""
        return Fernet(self.key).encrypt(data.encode()).decode()
    
    def _decrypt(self, data: str) -> str:
        """Déchiffre les données"""
        return Fernet(self.key).decrypt(data.encode()).decode()
    
    def authenticate(self) -> bool:
        """Gère l'authentification"""
        try:
            if os.path.exists(MASTER_KEY_FILE):
                with open(MASTER_KEY_FILE, "rb") as f:
                    data = f.read()
                    salt = data[:32]
                    encrypted_key = data[32:-64]
                    stored_hmac = data[-64:]
                
                password = getpass("Mot de passe maître: ")
                derived_key = self._derive_key(password, salt)
                
                self.key = Fernet(derived_key).decrypt(encrypted_key)
                if hashlib.blake2b(self.key).digest() != stored_hmac:
                    raise ValueError("Fichier de clé corrompu")
            else:
                self._create_new_vault()
            return True
        except Exception as e:
            print(f"Erreur d'authentification: {e}", file=sys.stderr)
            return False
    
    def _create_new_vault(self):
        """Crée un nouveau coffre-fort"""
        print("\nCréation d'un nouveau coffre-fort sécurisé")
        while True:
            password = getpass("Choisissez un mot de passe maître (min 12 caractères): ")
            if len(password) < 12:
                print("Le mot de passe doit contenir au moins 12 caractères", file=sys.stderr)
                continue
                
            verify = getpass("Confirmez le mot de passe: ")
            if password != verify:
                print("Les mots de passe ne correspondent pas", file=sys.stderr)
                continue
                
            salt = secrets.token_bytes(32)
            derived_key = self._derive_key(password, salt)
            self.key = Fernet.generate_key()
            
            with open(MASTER_KEY_FILE, "wb") as f:
                f.write(salt + Fernet(derived_key).encrypt(self.key) + hashlib.blake2b(self.key).digest())
            print("Coffre-fort créé avec succès")
            break
    
    def add_password(self, service: str, username: str, password: str, metadata: Optional[Dict] = None):
        """Ajoute un mot de passe"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO vault (service, username, password, metadata)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(service) DO UPDATE SET
                username = excluded.username,
                password = excluded.password,
                metadata = excluded.metadata
            """, (service, username, self._encrypt(password), self._encrypt(json.dumps(metadata or {}))))
    
    def get_password(self, service: str) -> Optional[Dict]:
        """Récupère un mot de passe"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("""
                SELECT username, password, metadata, created_at, updated_at
                FROM vault WHERE service = ?
            """, (service,)).fetchone()
        
        if not row:
            return None
            
        try:
            return {
                'username': row['username'],
                'password': self._decrypt(row['password']),
                'metadata': json.loads(self._decrypt(row['metadata'])),
                'created_at': row['created_at'],
                'updated_at': row['updated_at']
            }
        except:
            print("Erreur de déchiffrement - données potentiellement corrompues", file=sys.stderr)
            return None
    
    def delete_password(self, service: str) -> bool:
        """Supprime un mot de passe"""
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("DELETE FROM vault WHERE service = ?", (service,))
            return cur.rowcount > 0
    
    def list_services(self) -> List[Dict]:
        """Liste tous les services"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute("""
                SELECT service, created_at, updated_at 
                FROM vault ORDER BY service
            """).fetchall()]
    
    def security_audit(self) -> Dict[str, Any]:
        """Effectue un audit de sécurité"""
        results = {
            'total_entries': 0,
            'weak_passwords': [],
            'reused_passwords': {},
            'last_audit': datetime.now().isoformat()
        }
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            results['total_entries'] = conn.execute("SELECT COUNT(*) FROM vault").fetchone()[0]
            
            password_counter = {}
            for row in conn.execute("SELECT service, password FROM vault"):
                try:
                    pwd = self._decrypt(row['password'])
                    password_counter[pwd] = password_counter.get(pwd, 0) + 1
                    
                    entropy = PasswordGenerator().calculate_entropy(
                        pwd, 
                        string.ascii_letters + string.digits + PasswordGenerator.SYMBOLS
                    )
                    if entropy < 70:
                        results['weak_passwords'].append({
                            'service': row['service'],
                            'entropy': entropy
                        })
                except:
                    continue
            
            results['reused_passwords'] = {k: v for k, v in password_counter.items() if v > 1}
        
        return results

def handle_generate(args):
    """Gère la génération de mot de passe"""
    generator = PasswordGenerator()
    try:
        password = generator.generate_password(
            length=args.length,
            use_lowercase=not args.no_lower,
            use_uppercase=not args.no_upper,
            use_digits=not args.no_digits,
            use_symbols=not args.no_symbols,
            exclude_ambiguous=args.exclude_ambiguous,
            exclude_chars=args.exclude_chars,
            min_entropy=args.min_entropy
        )
        
        print(f"\nMot de passe généré: \033[92m{password}\033[0m")
        
        charset = generator._build_charset(
            not args.no_lower, not args.no_upper,
            not args.no_digits, not args.no_symbols,
            args.exclude_ambiguous, args.exclude_chars
        )
        entropy = generator.calculate_entropy(password, charset)
        print(f"Entropie: {entropy:.2f} bits")
        print(f"Combinaisons possibles: 2^{entropy:.0f} ≈ {2**entropy:.1e}")
        
    except Exception as e:
        print(f"\nErreur: {e}", file=sys.stderr)
        sys.exit(1)

def handle_add(manager):
    """Gère l'ajout d'un mot de passe"""
    print("\nAjout d'un nouveau mot de passe")
    service = input("Service (ex: google): ").strip()
    if not service:
        print("Le service est obligatoire", file=sys.stderr)
        return
        
    username = input("Nom d'utilisateur (optionnel): ").strip()
    password = getpass("Mot de passe (laisser vide pour générer): ")
    
    if not password:
        generator = PasswordGenerator()
        password = generator.generate_password()
        print(f"Mot de passe généré: \033[92m{password}\033[0m")
    
    metadata = {}
    while True:
        key = input("Métadonnée (clé, entrée pour terminer): ").strip()
        if not key:
            break
        value = input(f"{key}: ").strip()
        metadata[key] = value
    
    try:
        manager.add_password(service, username, password, metadata)
        print(f"\n✓ Mot de passe pour {service} enregistré")
    except Exception as e:
        print(f"\nErreur: {e}", file=sys.stderr)

def handle_get(manager, service):
    """Gère la récupération d'un mot de passe"""
    entry = manager.get_password(service)
    if not entry:
        print(f"\nAucune entrée trouvée pour {service}", file=sys.stderr)
        return
        
    print(f"\n\033[1mService:\033[0m {service}")
    print(f"\033[1mUtilisateur:\033[0m {entry['username']}")
    print(f"\033[1mMot de passe:\033[0m \033[92m{entry['password']}\033[0m")
    print(f"\033[1mCrée le:\033[0m {entry['created_at']}")
    print(f"\033[1mMis à jour le:\033[0m {entry['updated_at']}")
    
    if entry['metadata']:
        print("\n\033[1mMétadonnées:\033[0m")
        for k, v in entry['metadata'].items():
            print(f"  {k}: {v}")

def handle_list(manager):
    """Liste tous les services"""
    services = manager.list_services()
    if not services:
        print("\nAucun mot de passe enregistré")
        return
        
    print("\nServices enregistrés:")
    for service in services:
        print(f"- {service['service']} (créé le {service['created_at']})")

def handle_delete(manager, service):
    """Gère la suppression d'un mot de passe"""
    if not manager.delete_password(service):
        print(f"\nAucune entrée trouvée pour {service}", file=sys.stderr)
        return
        
    print(f"\n✓ Mot de passe pour {service} supprimé")

def handle_audit(manager):
    """Gère l'audit de sécurité"""
    print("\n⏳ Exécution de l'audit de sécurité...")
    audit = manager.security_audit()
    
    print(f"\n🔒 Audit de sécurité - {audit['last_audit']}")
    print(f"📊 Entrées totales: {audit['total_entries']}")
    
    if audit['weak_passwords']:
        print("\n⚠️ Mots de passe faibles détectés:")
        for item in audit['weak_passwords']:
            print(f"- {item['service']} (entropie: {item['entropy']:.1f} bits)")
    else:
        print("\n✅ Aucun mot de passe faible détecté")
    
    if audit['reused_passwords']:
        print("\n⚠️ Mots de passe réutilisés:")
        for pwd, count in audit['reused_passwords'].items():
            print(f"- Mot de passe utilisé {count} fois")
    else:
        print("\n✅ Aucune réutilisation de mot de passe détectée")

def interactive_mode(manager):
    """Mode interactif"""
    while True:
        print("\n=== SecurePass Manager ===")
        print("1. Ajouter un mot de passe")
        print("2. Récupérer un mot de passe")
        print("3. Lister les services")
        print("4. Supprimer un mot de passe")
        print("5. Audit de sécurité")
        print("6. Générer un mot de passe")
        print("7. Quitter")
        
        try:
            choice = input("> ").strip()
            
            if choice == "1":
                handle_add(manager)
            elif choice == "2":
                service = input("Service: ").strip()
                handle_get(manager, service)
            elif choice == "3":
                handle_list(manager)
            elif choice == "4":
                service = input("Service à supprimer: ").strip()
                handle_delete(manager, service)
            elif choice == "5":
                handle_audit(manager)
            elif choice == "6":
                handle_generate(argparse.Namespace(
                    length=DEFAULT_LENGTH,
                    no_lower=False,
                    no_upper=False,
                    no_digits=False,
                    no_symbols=False,
                    exclude_ambiguous=True,
                    exclude_chars='',
                    min_entropy=DEFAULT_MIN_ENTROPY
                ))
            elif choice == "7":
                break
            else:
                print("Option invalide", file=sys.stderr)
        except KeyboardInterrupt:
            print("\nOpération annulée")
            break
        except Exception as e:
            print(f"\nErreur: {e}", file=sys.stderr)

def main():
    """Point d'entrée principal"""
    parser = argparse.ArgumentParser(description="SecurePass - Gestionnaire de mots de passe sécurisé")
    subparsers = parser.add_subparsers(dest='command', required=False)
    
    # Génération de mot de passe
    gen_parser = subparsers.add_parser('generate', help='Générer un mot de passe sécurisé')
    gen_parser.add_argument("-l", "--length", type=int, default=DEFAULT_LENGTH, help="Longueur du mot de passe")
    gen_parser.add_argument("--no-lower", action="store_true", help="Exclure les minuscules")
    gen_parser.add_argument("--no-upper", action="store_true", help="Exclure les majuscules")
    gen_parser.add_argument("--no-digits", action="store_true", help="Exclure les chiffres")
    gen_parser.add_argument("--no-symbols", action="store_true", help="Exclure les symboles")
    gen_parser.add_argument("--exclude-ambiguous", action="store_true", help="Exclure les caractères ambigus")
    gen_parser.add_argument("--exclude-chars", type=str, default='', help="Caractères supplémentaires à exclure")
    gen_parser.add_argument("--min-entropy", type=float, default=DEFAULT_MIN_ENTROPY, help="Entropie minimale requise")
    gen_parser.set_defaults(func=handle_generate)
    
    # Mode interactif
    manage_parser = subparsers.add_parser('manage', help='Mode interactif')
    manage_parser.set_defaults(func=lambda _: interactive_mode(PasswordManager()))
    
    args = parser.parse_args()
    
    if hasattr(args, 'func'):
        args.func(args)
    else:
        interactive_mode(PasswordManager())

if __name__ == "__main__":
    main()