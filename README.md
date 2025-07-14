# Suite de Tests de Sécurité Web - Documentation

## ⚠️ AVERTISSEMENT IMPORTANT

**Ces outils sont conçus UNIQUEMENT pour tester la sécurité de VOS PROPRES applications ou celles pour lesquelles vous avez une autorisation écrite explicite.**

L'utilisation de ces outils sur des systèmes sans autorisation est **ILLÉGALE** et peut entraîner des poursuites judiciaires.

## 📋 Vue d'ensemble

Cette suite d'outils offre une gamme complète de tests de sécurité pour les applications web :

1. **Tests de sécurité basiques** - Headers, fichiers sensibles, configuration SSL
2. **Tests de vulnérabilités** - SQL Injection, XSS, traversée de répertoire
3. **Brute force intelligent** - Avec détection et contournement des protections
4. **Techniques d'évasion** - Pour tester la robustesse des défenses
5. **Génération de wordlists** - Création de dictionnaires personnalisés

## 🚀 Installation

### Prérequis
- Python 3.8 ou supérieur
- pip (gestionnaire de paquets Python)

### Installation des dépendances

```bash
# Cloner ou télécharger les scripts
git clone [votre-repo]
cd security-test-suite

# Activer l'environment
python -m venv venv  
venv\Scripts\activate  

# Installer les dépendances
pip install -r requirements.txt

# Ou installation minimale
pip install requests beautifulsoup4 colorama
```

### Installation optionnelle de Tor (pour l'anonymisation)

**Linux/Mac:**
```bash
# Ubuntu/Debian
sudo apt-get install tor

# macOS avec Homebrew
brew install tor

# Démarrer Tor
tor
```

**Windows:**
- Télécharger Tor Browser Bundle
- Ou installer Tor Expert Bundle

## 📚 Utilisation

### Mode Interactif (Recommandé pour débuter)

```bash
python advanced_quick_start.py
```

Le menu interactif vous guidera à travers les différentes options :
- Test rapide
- Test complet
- Brute force
- Génération de wordlists
- Analyse des rapports

### Mode Ligne de Commande

```bash
# Scan rapide
python advanced_quick_start.py --quick https://example.com

# Scan complet
python advanced_quick_start.py --full https://example.com

# Générer une wordlist
python advanced_quick_start.py --wordlist
```

### Scripts Individuels

#### 1. Test de Sécurité Standard
```bash
python security_tester.py
```
- Tests des headers de sécurité
- Recherche de fichiers sensibles
- Tests d'injection SQL et XSS basiques
- Test CORS

#### 2. Brute Force Intelligent
```bash
python intelligent_brute_forcer.py
```
- Détection automatique du type d'authentification
- Adaptation aux mécanismes anti-brute force
- Support multi-thread
- Génération de rapports détaillés

#### 3. Techniques d'Évasion
```bash
python evasion_techniques.py
```
- Rotation de sessions
- Variation des headers
- Timing réaliste
- Support des proxies et Tor

## 🔧 Configuration Avancée

### Fichier de Configuration (config.json)

Créez un fichier `config.json` pour personnaliser les paramètres :

```json
{
  "general": {
    "timeout": 10,
    "verify_ssl": false,
    "max_threads": 10
  },
  "brute_force": {
    "max_attempts": 1000,
    "delay_between_attempts": 0.5,
    "stop_on_success": true
  },
  "evasion": {
    "use_tor": false,
    "tor_control_port": 9051,
    "proxy_list": ["http://proxy1:8080", "http://proxy2:8080"]
  },
  "wordlists": {
    "default_usernames": ["admin", "root", "user"],
    "default_passwords": ["admin", "password", "123456"]
  }
}
```

### Variables d'Environnement

```bash
# Définir le timeout global
export SECURITY_TEST_TIMEOUT=30

# Activer le mode debug
export SECURITY_TEST_DEBUG=1

# Définir le nombre de threads
export SECURITY_TEST_THREADS=5
```

## 📊 Interprétation des Résultats

### Niveaux de Risque

- **🔴 Critique** : Vulnérabilités graves nécessitant une action immédiate
- **🟠 Élevé** : Problèmes importants à corriger rapidement
- **🟡 Moyen** : Améliorations recommandées
- **🟢 Faible** : Configuration généralement sécurisée

### Types de Vulnérabilités

#### 1. Injection SQL
- **Risque** : Accès non autorisé à la base de données
- **Solution** : Utiliser des requêtes préparées

#### 2. XSS (Cross-Site Scripting)
- **Risque** : Vol de sessions, défacement
- **Solution** : Échapper les sorties HTML

#### 3. Authentification Faible
- **Risque** : Accès non autorisé
- **Solution** : Mots de passe forts, 2FA, verrouillage de compte

#### 4. Headers de Sécurité Manquants
- **Risque** : Diverses attaques (clickjacking, MIME sniffing)
- **Solution** : Configurer les headers appropriés

## 🛡️ Bonnes Pratiques de Sécurité

### 1. Authentification
- Imposer des mots de passe forts (12+ caractères)
- Implémenter l'authentification à deux facteurs (2FA)
- Verrouiller les comptes après X tentatives échouées
- Utiliser des CAPTCHA après plusieurs échecs

### 2. Protection Anti-Brute Force
- Rate limiting par IP et par compte
- Délais progressifs entre les tentatives
- Surveillance des patterns d'attaque
- Notifications en temps réel

### 3. Headers de Sécurité
```nginx
# Exemple de configuration Nginx
add_header X-Frame-Options "DENY";
add_header X-Content-Type-Options "nosniff";
add_header X-XSS-Protection "1; mode=block";
add_header Strict-Transport-Security "max-age=31536000";
add_header Content-Security-Policy "default-src 'self'";
```

### 4. Validation des Entrées
- Valider côté serveur ET client
- Utiliser des listes blanches plutôt que noires
- Échapper les caractères spéciaux
- Limiter la taille des entrées

## 🔍 Exemples d'Utilisation

### Exemple 1 : Test Complet d'une Application

```python
# Script automatisé pour test complet
from advanced_security_tester import AdvancedSecurityTester

# Initialiser le testeur
tester = AdvancedSecurityTester("https://mon-app.com", threads=10)

# Exécuter tous les tests
results = tester.run_all_tests(include_brute_force=True)

# Générer le rapport
tester.generate_report()
```

### Exemple 2 : Brute Force avec Wordlist Personnalisée

```python
from intelligent_brute_forcer import IntelligentBruteForcer

# Créer une instance
bruteforcer = IntelligentBruteForcer("https://mon-app.com/login")

# Analyser la cible
bruteforcer.analyze_target("https://mon-app.com/login")

# Lancer le brute force avec wordlist
bruteforcer.smart_brute_force(
    "https://mon-app.com/login",
    wordlist_file="custom_wordlist.txt",
    max_attempts=500
)
```

### Exemple 3 : Test avec Techniques d'Évasion

```python
from evasion_techniques import EvasionTechniques

# Initialiser
evasion = EvasionTechniques("https://mon-app.com")

# Configurer Tor (optionnel)
evasion.setup_tor()

# Créer un pool de sessions
evasion.create_session_pool(size=20)

# Fonction de login personnalisée
def my_login_function(session, username, password):
    # Votre logique de login ici
    pass

# Lancer l'attaque distribuée
credentials = [("admin", "pass1"), ("user", "pass2")]
stats = evasion.distributed_attack(my_login_function, credentials, threads=5)
```

## 📈 Métriques et Monitoring

### Indicateurs Clés
- **Taux de réussite** : Pourcentage de logins réussis
- **Temps de réponse** : Détection des rate limits
- **Patterns détectés** : Mécanismes de protection identifiés

### Export des Résultats
Les rapports sont générés en format JSON pour faciliter l'intégration :

```json
{
  "target": "https://example.com",
  "date": "2024-01-15T10:30:00",
  "vulnerabilities": [...],
  "stats": {
    "attempts": 1000,
    "successes": 2,
    "rate_limits": 15
  }
}
```

## 🚨 Dépannage

### Problèmes Courants

1. **"Module not found"**
   ```bash
   pip install -r requirements.txt
   ```

2. **"SSL Certificate Error"**
   - Ajouter `verify=False` dans le code
   - Ou installer les certificats : `pip install certifi`

3. **"Rate limit atteint"**
   - Augmenter les délais entre requêtes
   - Utiliser des proxies ou Tor
   - Réduire le nombre de threads

4. **"Connection timeout"**
   - Vérifier la connectivité réseau
   - Augmenter le timeout
   - Vérifier si le site est accessible

## 📝 Contribution et Support

### Signaler un Bug
1. Vérifier que le bug n'est pas déjà signalé
2. Fournir les logs détaillés
3. Indiquer la version de Python et l'OS

### Proposer des Améliorations
- Les pull requests sont les bienvenues
- Suivre les conventions de code Python (PEP 8)
- Ajouter des tests pour les nouvelles fonctionnalités

## 📜 Licence et Responsabilité

Ces outils sont fournis "tels quels" à des fins éducatives uniquement. L'auteur décline toute responsabilité pour :
- L'utilisation illégale ou non autorisée
- Les dommages causés par l'utilisation de ces outils
- Les conséquences légales de leur utilisation

**UTILISEZ CES OUTILS DE MANIÈRE RESPONSABLE ET ÉTHIQUE**

## 🔗 Ressources Supplémentaires

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Disclosure Guidelines](https://www.hackerone.com/disclosure-guidelines)
- [Bug Bounty Programs](https://www.bugcrowd.com/bug-bounty-list/)

---

*Remember: With great power comes great responsibility. Always hack ethically!* 🎩✨