## 🛡️ Sécurité Commune aux Deux Versions

### Principes de Sécurité
1. **Chiffrement Fort** : AES-256 avec mode GCM
2. **Dérivation de Clé** : PBKDF2-HMAC-SHA512 avec 310 000 itérations
3. **Protection des Données** :
   - Vérification d'intégrité HMAC
   - Salage cryptographique
   - Protection contre les attaques par timing
4. **Gestion Sécurisée des Secrets** :
   - Effacement mémoire après utilisation
   - Protection contre les dump mémoire

### Bonnes Pratiques
- Utilisez toujours un mot de passe maître fort (12+ caractères)
- Ne partagez jamais votre fichier `master.key`
- Maintenez le logiciel à jour
- Sauvegardez régulièrement votre coffre-fort
- Activez l'authentification à deux facteurs sur les comptes sensibles

### Audit de Sécurité
Le système inclut un audit de sécurité intégré qui vérifie :
1. La force des mots de passe (entropie < 70 bits)
2. Les réutilisations de mots de passe
3. L'ancienneté des identifiants
4. La conformité aux politiques de sécurité

## 📜 License
Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 🙏 Remerciements
- L'équipe Cryptography pour la bibliothèque de chiffrement
- La communauté PyQt pour l'excellente bibliothèque GUI
- Les chercheurs en sécurité pour leurs recommandations OWASP