# SecurePass CLI - Gestionnaire de Mots de Passe en Ligne de Commande

SecurePass CLI est un gestionnaire de mots de passe professionnel fonctionnant en ligne de commande. Il offre des fonctionnalités avancées de génération et de stockage sécurisé de mots de passe.

## Fonctionnalités

- 🔐 **Génération de mots de passe sécurisés**
  - Personnalisation de la longueur et des caractères
  - Exclusion des caractères ambigus
  - Calcul d'entropie pour mesurer la force
- 🗃️ **Stockage sécurisé**
  - Chiffrement AES-256
  - Clé maître dérivée avec PBKDF2-HMAC-SHA512
  - Vérification d'intégrité avec BLAKE2b
- 🔍 **Gestion des identifiants**
  - Ajout/suppression de comptes
  - Recherche dans le coffre-fort
  - Audit de sécurité automatisé
- 📊 **Statistiques avancées**
  - Détection des mots de passe faibles
  - Identification des réutilisations
  - Historique des modifications

## Prérequis

- Python 3.8+
- Système d'exploitation : Windows, macOS, Linux

## Installation

1. Clonez le dépôt :
```bash
git clone https://github.com/LeZelote01/SecurePass.git
cd SecurePass/CLI
```
2. Installez les dépendances :
```bash
pip install -r requirements.txt
```

## Utilisation

### Génération de mot de passe

```bash
python securepass_cli.py generate --length 20 --min-entropy 100
```

- ### Options disponibles :
  - **length** : Longueur du mot de passe (défaut: 16)
  - **min-entropy** : Entropie minimale requise (défaut: 80)
  - **no-lower** : Exclure les minuscules
  - **no-upper** : Exclure les majuscules
  - **no-digits** : Exclure les chiffres
  - **no-symbols** : Exclure les symboles
  - **exclude-ambiguous** : Exclure les caractères ambigus (l,1,I,O,0)

### Gestionnaire interactif
```bash
python securepass_cli.py manage
```

- ### Menu interactif :
  1. Ajouter un mot de passe
  2. Récupérer un mot de passe
  3. Lister les services
  4. Supprimer une entrée
  5. Audit de sécurité
  6. Générer un nouveau mot de passe
  7. Quitter

