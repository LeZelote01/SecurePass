
## 💻 SecurePass GUI - Version Graphique

# SecurePass GUI - Gestionnaire de Mots de Passe Graphique

SecurePass GUI offre une interface moderne et intuitive pour la gestion de vos mots de passe, avec des fonctionnalités avancées de sécurité et une expérience utilisateur soignée.

## Fonctionnalités

- 🖼️ **Interface moderne**
  - Design professionnel avec effets visuels
  - Arrière-plan personnalisable
  - Animations fluides
- 🔐 **Gestion sécurisée**
  - Chiffrement AES-256 avec authentification
  - Audit de sécurité visuel
  - Détection des vulnérabilités
- 🛠️ **Outils intégrés**
  - Générateur de mots de passe avec options avancées
  - Calcul d'entropie en temps réel
  - Copie sécurisée dans le presse-papiers
- 📊 **Tableau de bord**
  - Statistiques de sécurité
  - Historique des modifications
  - Vue chronologique des entrées

## Prérequis

- Python 3.8+
- Système d'exploitation : Windows, macOS, Linux
- Résolution d'écran : 1280x720 minimum

## Installation

1. Clonez le dépôt :
```bash
git clone https://github.com/LeZelote01/SecurePass.git
cd SecurePass/GUI
```
2. Installez les dépendances :
```bash
pip install -r requirements.txt
```

## Lancement

```bash
python securepass_gui.py
```

## Guide d'Utilisation

### Authentification

À la première utilisation, créez un mot de passe maître fort (12+ caractères). Ce mot de passe sera utilisé pour déverrouiller votre coffre-fort.

### Onglets Principaux

1. **Accueil**
- Tableau de bord avec statistiques
- Accès rapide aux fonctions principales
- Vue d'ensemble de la sécurité

2. **Générateur**
- Personnalisation des paramètres de génération
- Visualisation de la force du mot de passe
- Options d'enregistrement direct dans le coffre-fort

3. **Coffre-fort**
- Liste complète de vos identifiants
- Fonction de recherche instantanée
- Détails complets par service

4. **Audit**
- Analyse complète de la sécurité
- Détection des mots de passe faibles
- Identification des réutilisations
