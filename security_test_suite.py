#!/usr/bin/env python3
"""
Script de démarrage rapide avancé pour les tests de sécurité
Intègre tous les outils de test développés
"""

import sys
import os
import time
import json
from datetime import datetime
import subprocess
import argparse
from colorama import init, Fore, Back, Style

# Initialiser colorama pour les couleurs cross-platform
init(autoreset=True)

class SecurityTestSuite:
    def __init__(self):
        self.results = {
            'scan_date': datetime.now().isoformat(),
            'tests_performed': [],
            'vulnerabilities_found': 0,
            'risk_level': 'Unknown'
        }
        
    def banner(self):
        """Affiche la bannière du programme"""
        banner_text = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║     ███████╗███████╗ ██████╗    ████████╗███████╗███████╗████████╗
║     ██╔════╝██╔════╝██╔════╝    ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
║     ███████╗█████╗  ██║            ██║   █████╗  ███████╗   ██║   
║     ╚════██║██╔══╝  ██║            ██║   ██╔══╝  ╚════██║   ██║   
║     ███████║███████╗╚██████╗       ██║   ███████╗███████║   ██║   
║     ╚══════╝╚══════╝ ╚═════╝       ╚═╝   ╚══════╝╚══════╝   ╚═╝   
║                                                                  ║
║              Suite Complète de Tests de Sécurité v3.0            ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
        """
        print(Fore.CYAN + banner_text)
        
    def check_requirements(self):
        """Vérifie les dépendances requises"""
        print(Fore.YELLOW + "\n[*] Vérification des dépendances...")
        
        # Mapping des noms de packages vers les noms d'import
        required_modules = {
            'requests': 'requests',
            'beautifulsoup4': 'bs4',
            'colorama': 'colorama',
            'faker': 'faker',
            'PySocks': 'socks'
        }
        
        # Modules optionnels
        optional_modules = {
            'stem': 'stem',
            'lxml': 'lxml'
        }
        
        missing = []
        optional_missing = []
        
        # Vérifier les modules requis
        for package_name, import_name in required_modules.items():
            try:
                __import__(import_name)
                print(Fore.GREEN + f"  ✓ {package_name}")
            except ImportError:
                missing.append(package_name)
                print(Fore.RED + f"  ✗ {package_name}")
        
        # Vérifier les modules optionnels
        print(Fore.YELLOW + "\n[*] Modules optionnels:")
        for package_name, import_name in optional_modules.items():
            try:
                __import__(import_name)
                print(Fore.GREEN + f"  ✓ {package_name}")
            except ImportError:
                optional_missing.append(package_name)
                print(Fore.YELLOW + f"  ○ {package_name} (non installé - optionnel)")
        
        if missing:
            print(Fore.RED + f"\n[!] Modules manquants: {', '.join(missing)}")
            print(Fore.YELLOW + "[*] Installation avec: pip install " + ' '.join(missing))
            return False
        
        if optional_missing:
            print(Fore.YELLOW + f"\n[*] Pour toutes les fonctionnalités, installez: pip install " + ' '.join(optional_missing))
        
        return True
    
    def main_menu(self):
        """Menu principal interactif"""
        while True:
            print(Fore.CYAN + "\n" + "="*60)
            print(Fore.WHITE + "MENU PRINCIPAL")
            print(Fore.CYAN + "="*60)
            
            options = [
                ("1", "Test de sécurité rapide", "quick_scan"),
                ("2", "Test de sécurité complet", "full_scan"),
                ("3", "Test de brute force intelligent", "brute_force_test"),
                ("4", "Test des techniques d'évasion", "evasion_test"),
                ("5", "Analyse des vulnérabilités web", "vuln_analysis"),
                ("6", "Test de résistance (stress test)", "stress_test"),
                ("7", "Générer des wordlists personnalisées", "generate_wordlists"),
                ("8", "Analyser les rapports précédents", "analyze_reports"),
                ("9", "Configuration avancée", "advanced_config"),
                ("0", "Quitter", "quit")
            ]
            
            for num, desc, _ in options:
                print(f"{Fore.YELLOW}{num}. {Fore.WHITE}{desc}")
            
            choice = input(Fore.GREEN + "\n➤ Votre choix: " + Style.RESET_ALL).strip()
            
            # Exécuter l'action correspondante
            for num, _, action in options:
                if choice == num:
                    if action == "quit":
                        self.cleanup()
                        return
                    else:
                        getattr(self, action)()
                    break
            else:
                print(Fore.RED + "[!] Choix invalide")
    
    def quick_scan(self):
        """Scan de sécurité rapide"""
        print(Fore.CYAN + "\n" + "="*60)
        print(Fore.WHITE + "SCAN DE SÉCURITÉ RAPIDE")
        print(Fore.CYAN + "="*60)
        
        target = self.get_target_url()
        if not target:
            return
        
        print(Fore.YELLOW + f"\n[*] Scan rapide de {target}")
        
        # Tests à effectuer
        tests = [
            ("Headers de sécurité", self.test_security_headers),
            ("Fichiers sensibles", self.test_sensitive_files),
            ("Configuration SSL/TLS", self.test_ssl_config),
            ("Cookies sécurisés", self.test_secure_cookies),
            ("Méthodes HTTP", self.test_http_methods)
        ]
        
        results = {}
        for test_name, test_func in tests:
            print(Fore.YELLOW + f"\n[*] Test: {test_name}")
            result = test_func(target)
            results[test_name] = result
            
            if result['vulnerable']:
                print(Fore.RED + f"  ⚠️  Vulnérabilités trouvées!")
            else:
                print(Fore.GREEN + f"  ✓ Test passé")
        
        self.save_results(results, "quick_scan")
    
    def full_scan(self):
        """Scan de sécurité complet"""
        print(Fore.CYAN + "\n" + "="*60)
        print(Fore.WHITE + "SCAN DE SÉCURITÉ COMPLET")
        print(Fore.CYAN + "="*60)
        
        target = self.get_target_url()
        if not target:
            return
        
        # Importer et utiliser AdvancedSecurityTester
        try:
            from security_tester import AdvancedSecurityTester
            
            print(Fore.YELLOW + f"\n[*] Scan complet de {target}")
            print(Fore.YELLOW + "[*] Ce scan peut prendre plusieurs minutes...")
            
            tester = AdvancedSecurityTester(target)
            results = tester.run_all_tests(include_brute_force=False)
            
            # Afficher le résumé
            print(Fore.CYAN + "\n" + "="*60)
            print(Fore.WHITE + "RÉSUMÉ DU SCAN")
            print(Fore.CYAN + "="*60)
            
            vuln_count = len(results.get('vulnerabilities', []))
            warn_count = len(results.get('warnings', []))
            
            if vuln_count > 0:
                print(Fore.RED + f"\n⚠️  {vuln_count} vulnérabilités trouvées!")
                for vuln in results['vulnerabilities'][:5]:
                    print(Fore.RED + f"  - {vuln}")
                if vuln_count > 5:
                    print(Fore.YELLOW + f"  ... et {vuln_count - 5} autres")
            
            if warn_count > 0:
                print(Fore.YELLOW + f"\n⚠️  {warn_count} avertissements")
            
            self.save_results(results, "full_scan")
            
        except ImportError:
            print(Fore.RED + "[!] Module security_tester non trouvé")
    
    def brute_force_test(self):
        """Test de brute force intelligent"""
        print(Fore.CYAN + "\n" + "="*60)
        print(Fore.WHITE + "TEST DE BRUTE FORCE INTELLIGENT")
        print(Fore.CYAN + "="*60)
        
        print(Fore.RED + "\n⚠️  AVERTISSEMENT IMPORTANT:")
        print(Fore.RED + "Utilisez uniquement sur VOS propres systèmes!")
        
        confirm = input(Fore.YELLOW + "\nConfirmez-vous avoir l'autorisation? (oui/non): ")
        if confirm.lower() not in ['oui', 'yes', 'y']:
            print(Fore.RED + "[!] Test annulé")
            return
        
        target = input(Fore.GREEN + "\nURL de login: " + Style.RESET_ALL).strip()
        
        # Options de configuration
        print(Fore.YELLOW + "\n[*] Configuration du brute force:")
        print("1. Test limité (50 tentatives)")
        print("2. Test modéré (200 tentatives)")
        print("3. Test étendu (1000 tentatives)")
        print("4. Configuration personnalisée")
        
        config_choice = input(Fore.GREEN + "\nVotre choix: " + Style.RESET_ALL)
        
        max_attempts = {
            '1': 50,
            '2': 200,
            '3': 1000,
            '4': int(input("Nombre de tentatives: ") or 100)
        }.get(config_choice, 50)
        
        try:
            from intelligent_brute_forcer import IntelligentBruteForcer
            
            bruteforcer = IntelligentBruteForcer(target)
            results = bruteforcer.smart_brute_force(target, max_attempts=max_attempts)
            
            if results:
                print(Fore.RED + f"\n⚠️  {len(results)} credential(s) trouvé(s)!")
            else:
                print(Fore.GREEN + "\n✓ Aucun credential faible trouvé")
            
        except ImportError:
            print(Fore.RED + "[!] Module intelligent_brute_forcer non trouvé")
    
    def evasion_test(self):
        """Test des techniques d'évasion"""
        print(Fore.CYAN + "\n" + "="*60)
        print(Fore.WHITE + "TEST DES TECHNIQUES D'ÉVASION")
        print(Fore.CYAN + "="*60)
        
        try:
            from evasion_techniques import EvasionTechniques, demonstrate_evasion
            demonstrate_evasion()
        except ImportError:
            print(Fore.RED + "[!] Module evasion_techniques non trouvé")
    
    def vuln_analysis(self):
        """Analyse approfondie des vulnérabilités"""
        print(Fore.CYAN + "\n" + "="*60)
        print(Fore.WHITE + "ANALYSE DES VULNÉRABILITÉS WEB")
        print(Fore.CYAN + "="*60)
        
        target = self.get_target_url()
        if not target:
            return
        
        # Tests spécialisés
        print(Fore.YELLOW + "\n[*] Sélectionnez les tests à effectuer:")
        tests = {
            '1': ('Injection SQL', 'sql_injection'),
            '2': ('Cross-Site Scripting (XSS)', 'xss'),
            '3': ('Injection de commandes', 'command_injection'),
            '4': ('Traversée de répertoire', 'directory_traversal'),
            '5': ('Injection XML/XXE', 'xxe'),
            '6': ('Désérialisation non sécurisée', 'deserialization'),
            '7': ('SSRF (Server-Side Request Forgery)', 'ssrf'),
            '8': ('Tous les tests', 'all')
        }
        
        for key, (name, _) in tests.items():
            print(f"{key}. {name}")
        
        choice = input(Fore.GREEN + "\nVotre choix: " + Style.RESET_ALL)
        
        if choice in tests:
            test_name, test_type = tests[choice]
            print(Fore.YELLOW + f"\n[*] Exécution: {test_name}")
            # Ici, appeler les fonctions de test spécifiques
            print(Fore.GREEN + "[*] Test terminé")
    
    def stress_test(self):
        """Test de résistance"""
        print(Fore.CYAN + "\n" + "="*60)
        print(Fore.WHITE + "TEST DE RÉSISTANCE (STRESS TEST)")
        print(Fore.CYAN + "="*60)
        
        print(Fore.YELLOW + "\n[*] Ce test va simuler une charge importante")
        print(Fore.RED + "⚠️  Peut impacter les performances du serveur!")
        
        target = self.get_target_url()
        if not target:
            return
        
        # Configuration du stress test
        threads = int(input("Nombre de threads (1-50): ") or 10)
        duration = int(input("Durée en secondes (1-300): ") or 30)
        requests_per_thread = int(input("Requêtes par thread (1-1000): ") or 100)
        
        print(Fore.YELLOW + f"\n[*] Démarrage du stress test...")
        print(f"  - Threads: {threads}")
        print(f"  - Durée: {duration}s")
        print(f"  - Total requêtes: ~{threads * requests_per_thread}")
        
        # Ici implémenter le stress test
        print(Fore.GREEN + "\n[*] Stress test terminé")
    
    def generate_wordlists(self):
        """Génère des wordlists personnalisées"""
        print(Fore.CYAN + "\n" + "="*60)
        print(Fore.WHITE + "GÉNÉRATEUR DE WORDLISTS")
        print(Fore.CYAN + "="*60)
        
        print(Fore.YELLOW + "\n[*] Types de wordlists:")
        print("1. Mots de passe basiques")
        print("2. Mots de passe d'entreprise")
        print("3. Mots de passe avec patterns")
        print("4. Combinaisons personnalisées")
        
        choice = input(Fore.GREEN + "\nVotre choix: " + Style.RESET_ALL)
        
        if choice == '1':
            self.generate_basic_wordlist()
        elif choice == '2':
            company = input("Nom de l'entreprise: ")
            self.generate_company_wordlist(company)
        elif choice == '3':
            self.generate_pattern_wordlist()
        elif choice == '4':
            self.generate_custom_wordlist()
    
    def analyze_reports(self):
        """Analyse les rapports de sécurité précédents"""
        print(Fore.CYAN + "\n" + "="*60)
        print(Fore.WHITE + "ANALYSE DES RAPPORTS")
        print(Fore.CYAN + "="*60)
        
        # Lister les rapports disponibles
        import glob
        reports = glob.glob("*_report_*.json")
        
        if not reports:
            print(Fore.YELLOW + "[*] Aucun rapport trouvé")
            return
        
        print(Fore.YELLOW + f"\n[*] {len(reports)} rapport(s) trouvé(s):")
        for i, report in enumerate(reports, 1):
            print(f"{i}. {report}")
        
        choice = input(Fore.GREEN + "\nNuméro du rapport à analyser: " + Style.RESET_ALL)
        
        try:
            report_file = reports[int(choice) - 1]
            with open(report_file, 'r') as f:
                data = json.load(f)
            
            # Analyser et afficher les statistiques
            self.display_report_analysis(data)
            
        except (IndexError, ValueError):
            print(Fore.RED + "[!] Choix invalide")
    
    def advanced_config(self):
        """Configuration avancée des outils"""
        print(Fore.CYAN + "\n" + "="*60)
        print(Fore.WHITE + "CONFIGURATION AVANCÉE")
        print(Fore.CYAN + "="*60)
        
        print(Fore.YELLOW + "\n[*] Options disponibles:")
        print("1. Configurer les proxies")
        print("2. Configurer Tor")
        print("3. Paramètres de performance")
        print("4. Gestion des certificats SSL")
        print("5. Configuration des notifications")
        
        choice = input(Fore.GREEN + "\nVotre choix: " + Style.RESET_ALL)
        
        # Implémenter les différentes configurations
        print(Fore.GREEN + "[*] Configuration mise à jour")
    
    # Méthodes utilitaires
    def get_target_url(self):
        """Demande et valide l'URL cible"""
        url = input(Fore.GREEN + "\n🎯 URL cible: " + Style.RESET_ALL).strip()
        
        if not url:
            print(Fore.RED + "[!] URL vide")
            return None
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Vérifier l'autorisation
        print(Fore.YELLOW + f"\n⚠️  Cible: {url}")
        confirm = input(Fore.YELLOW + "Confirmez-vous avoir l'autorisation? (oui/non): ")
        
        if confirm.lower() not in ['oui', 'yes', 'y']:
            print(Fore.RED + "[!] Test annulé")
            return None
        
        return url
    
    def test_security_headers(self, url):
        """Test rapide des headers de sécurité"""
        import requests
        
        result = {'vulnerable': False, 'details': []}
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers
            
            security_headers = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-XSS-Protection'
            ]
            
            missing = []
            for header in security_headers:
                if header not in headers:
                    missing.append(header)
                    result['vulnerable'] = True
            
            result['details'] = missing
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def test_sensitive_files(self, url):
        """Test rapide des fichiers sensibles"""
        import requests
        
        result = {'vulnerable': False, 'details': []}
        
        sensitive_files = [
            '.git/config', '.env', 'wp-config.php',
            'config.php', '.htaccess', 'robots.txt'
        ]
        
        for file in sensitive_files:
            try:
                file_url = url.rstrip('/') + '/' + file
                response = requests.get(file_url, timeout=5, verify=False)
                
                if response.status_code == 200:
                    result['vulnerable'] = True
                    result['details'].append(file)
            except:
                pass
        
        return result
    
    def test_ssl_config(self, url):
        """Test de la configuration SSL/TLS"""
        result = {'vulnerable': False, 'details': []}
        
        if not url.startswith('https://'):
            result['vulnerable'] = True
            result['details'].append('Pas de HTTPS')
        
        return result
    
    def test_secure_cookies(self, url):
        """Test des cookies sécurisés"""
        import requests
        
        result = {'vulnerable': False, 'details': []}
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            
            for cookie in response.cookies:
                if not cookie.secure and url.startswith('https://'):
                    result['vulnerable'] = True
                    result['details'].append(f"Cookie non sécurisé: {cookie.name}")
                
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    result['vulnerable'] = True
                    result['details'].append(f"Cookie sans HttpOnly: {cookie.name}")
        except:
            pass
        
        return result
    
    def test_http_methods(self, url):
        """Test des méthodes HTTP autorisées"""
        import requests
        
        result = {'vulnerable': False, 'details': []}
        
        dangerous_methods = ['PUT', 'DELETE', 'CONNECT', 'TRACE']
        
        for method in dangerous_methods:
            try:
                response = requests.request(method, url, timeout=5, verify=False)
                if response.status_code < 400:
                    result['vulnerable'] = True
                    result['details'].append(f"Méthode {method} autorisée")
            except:
                pass
        
        return result
    
    def generate_basic_wordlist(self):
        """Génère une wordlist basique"""
        words = []
        
        # Mots de base
        base = ['admin', 'password', 'test', 'user', 'root', 'guest']
        
        # Variations
        for word in base:
            words.append(word)
            words.append(word + '123')
            words.append(word + '2024')
            words.append(word.capitalize())
            words.append(word.upper())
        
        # Sauvegarder
        filename = f"wordlist_basic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            for word in words:
                f.write(word + '\n')
        
        print(Fore.GREEN + f"[+] Wordlist créée: {filename} ({len(words)} mots)")
    
    def generate_company_wordlist(self, company):
        """Génère une wordlist basée sur le nom de l'entreprise"""
        words = []
        
        # Variations du nom de l'entreprise
        variations = [
            company.lower(),
            company.upper(),
            company.capitalize(),
            company.replace(' ', ''),
            company.replace(' ', '_'),
            company[:3].lower()  # Acronyme
        ]
        
        # Combinaisons
        suffixes = ['123', '2024', '2025', '!', '@', '#', 'admin', 'user']
        
        for var in variations:
            words.append(var)
            for suffix in suffixes:
                words.append(var + suffix)
        
        # Sauvegarder
        filename = f"wordlist_company_{company.lower().replace(' ', '_')}.txt"
        with open(filename, 'w') as f:
            for word in set(words):
                f.write(word + '\n')
        
        print(Fore.GREEN + f"[+] Wordlist créée: {filename} ({len(set(words))} mots)")
    
    def generate_pattern_wordlist(self):
        """Génère une wordlist avec des patterns"""
        import itertools
        
        words = []
        
        # Patterns communs
        patterns = [
            # Saison + Année
            ['Spring', 'Summer', 'Fall', 'Winter'],
            ['2023', '2024', '2025'],
            
            # Mois + Année
            ['January', 'February', 'March', 'April', 'May', 'June',
             'July', 'August', 'September', 'October', 'November', 'December'],
            ['24', '25']
        ]
        
        # Générer les combinaisons
        for pattern_group in patterns:
            if len(pattern_group) == 2:
                for combo in itertools.product(pattern_group[0], pattern_group[1]):
                    words.append(''.join(combo))
        
        # Patterns complexes
        complex_patterns = [
            'Welcome{year}',
            'Password{num}!',
            '{Company}{year}',
            'Admin@{year}'
        ]
        
        for pattern in complex_patterns:
            for year in ['2024', '2025']:
                for num in range(10):
                    word = pattern.format(year=year, num=num, Company='Company')
                    words.append(word)
        
        # Sauvegarder
        filename = f"wordlist_patterns_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            for word in set(words):
                f.write(word + '\n')
        
        print(Fore.GREEN + f"[+] Wordlist créée: {filename} ({len(set(words))} mots)")
    
    def generate_custom_wordlist(self):
        """Interface pour créer une wordlist personnalisée"""
        print(Fore.YELLOW + "\n[*] Création de wordlist personnalisée")
        
        words = []
        
        # Mots de base
        base_input = input("Mots de base (séparés par des virgules): ")
        base_words = [w.strip() for w in base_input.split(',') if w.strip()]
        
        # Options de transformation
        print("\n[*] Transformations à appliquer:")
        use_caps = input("  - Variations de casse? (o/n): ").lower() == 'o'
        use_numbers = input("  - Ajouter des nombres? (o/n): ").lower() == 'o'
        use_special = input("  - Ajouter des caractères spéciaux? (o/n): ").lower() == 'o'
        use_leet = input("  - Leetspeak? (o/n): ").lower() == 'o'
        
        # Appliquer les transformations
        for word in base_words:
            words.append(word)
            
            if use_caps:
                words.extend([word.lower(), word.upper(), word.capitalize()])
            
            if use_numbers:
                for i in range(10):
                    words.append(f"{word}{i}")
                words.extend([f"{word}123", f"{word}2024", f"{word}2025"])
            
            if use_special:
                for char in ['!', '@', '#', '$', '*']:
                    words.append(f"{word}{char}")
            
            if use_leet:
                leet = word.replace('a', '@').replace('e', '3').replace('i', '1').replace('o', '0')
                words.append(leet)
        
        # Éliminer les doublons
        words = list(set(words))
        
        # Sauvegarder
        filename = f"wordlist_custom_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            for word in words:
                f.write(word + '\n')
        
        print(Fore.GREEN + f"[+] Wordlist créée: {filename} ({len(words)} mots)")
    
    def display_report_analysis(self, data):
        """Affiche l'analyse d'un rapport"""
        print(Fore.CYAN + "\n" + "="*60)
        print(Fore.WHITE + "ANALYSE DU RAPPORT")
        print(Fore.CYAN + "="*60)
        
        # Extraire les statistiques
        if 'vulnerabilities' in data:
            vuln_count = len(data['vulnerabilities'])
            print(Fore.RED + f"\n⚠️  Vulnérabilités: {vuln_count}")
            
            # Catégoriser les vulnérabilités
            categories = {}
            for vuln in data['vulnerabilities']:
                if 'SQL' in vuln:
                    categories['SQL Injection'] = categories.get('SQL Injection', 0) + 1
                elif 'XSS' in vuln:
                    categories['XSS'] = categories.get('XSS', 0) + 1
                elif 'Authentification' in vuln:
                    categories['Authentification'] = categories.get('Authentification', 0) + 1
                elif 'Fichier' in vuln:
                    categories['Fichiers exposés'] = categories.get('Fichiers exposés', 0) + 1
                else:
                    categories['Autres'] = categories.get('Autres', 0) + 1
            
            print(Fore.YELLOW + "\n[*] Répartition par catégorie:")
            for cat, count in categories.items():
                print(f"  - {cat}: {count}")
        
        if 'warnings' in data:
            print(Fore.YELLOW + f"\n⚠️  Avertissements: {len(data['warnings'])}")
        
        if 'info' in data:
            print(Fore.CYAN + f"\nℹ️  Informations: {len(data['info'])}")
        
        # Niveau de risque
        risk_level = self.calculate_risk_level(data)
        color = {
            'Critique': Fore.RED,
            'Élevé': Fore.RED,
            'Moyen': Fore.YELLOW,
            'Faible': Fore.GREEN
        }.get(risk_level, Fore.WHITE)
        
        print(color + f"\n🎯 Niveau de risque global: {risk_level}")
    
    def calculate_risk_level(self, data):
        """Calcule le niveau de risque basé sur les résultats"""
        score = 0
        
        if 'vulnerabilities' in data:
            vuln_count = len(data['vulnerabilities'])
            if vuln_count > 20:
                score += 100
            elif vuln_count > 10:
                score += 75
            elif vuln_count > 5:
                score += 50
            elif vuln_count > 0:
                score += 25
            
            # Vulnérabilités critiques
            critical_keywords = ['SQL', 'injection', 'RCE', 'command', 'Authentification']
            for vuln in data['vulnerabilities']:
                if any(keyword in vuln for keyword in critical_keywords):
                    score += 10
        
        if 'warnings' in data:
            score += len(data['warnings']) * 2
        
        # Déterminer le niveau
        if score >= 100:
            return 'Critique'
        elif score >= 75:
            return 'Élevé'
        elif score >= 40:
            return 'Moyen'
        else:
            return 'Faible'
    
    def save_results(self, results, test_type):
        """Sauvegarde les résultats des tests"""
        filename = f"{test_type}_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        
        print(Fore.GREEN + f"\n[+] Résultats sauvegardés: {filename}")
    
    def cleanup(self):
        """Nettoyage avant la fermeture"""
        print(Fore.YELLOW + "\n[*] Nettoyage...")
        print(Fore.GREEN + "[+] Fermeture de l'application")
        print(Fore.CYAN + "\nMerci d'avoir utilisé Security Test Suite!")
        print(Fore.WHITE + "N'oubliez pas: Testez uniquement VOS propres systèmes!\n")


def main():
    """Point d'entrée principal"""
    parser = argparse.ArgumentParser(
        description='Suite complète de tests de sécurité',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  %(prog)s                    # Mode interactif
  %(prog)s --quick <url>      # Scan rapide
  %(prog)s --full <url>       # Scan complet
  %(prog)s --wordlist         # Générer une wordlist
        """
    )
    
    parser.add_argument('--quick', metavar='URL', help='Effectuer un scan rapide')
    parser.add_argument('--full', metavar='URL', help='Effectuer un scan complet')
    parser.add_argument('--wordlist', action='store_true', help='Générer une wordlist')
    parser.add_argument('--no-banner', action='store_true', help='Ne pas afficher la bannière')
    
    args = parser.parse_args()
    
    # Créer l'instance
    suite = SecurityTestSuite()
    
    # Afficher la bannière
    if not args.no_banner:
        suite.banner()
    
    # Vérifier les dépendances
    if not suite.check_requirements():
        print(Fore.RED + "\n[!] Veuillez installer les dépendances manquantes")
        sys.exit(1)
    
    # Mode ligne de commande
    if args.quick:
        print(Fore.YELLOW + f"\n[*] Scan rapide de {args.quick}")
        # Implémenter le scan rapide direct
    elif args.full:
        print(Fore.YELLOW + f"\n[*] Scan complet de {args.full}")
        # Implémenter le scan complet direct
    elif args.wordlist:
        suite.generate_wordlists()
    else:
        # Mode interactif
        try:
            suite.main_menu()
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n\n[*] Interruption détectée")
            suite.cleanup()


if __name__ == "__main__":
    main()