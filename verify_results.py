#!/usr/bin/env python3
"""
Script pour vérifier les résultats du scan de sécurité
et distinguer les vraies vulnérabilités des faux positifs
"""

import requests
import json
from urllib.parse import urljoin

class SecurityResultsVerifier:
    def __init__(self, base_url, report_file):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        
        # Charger le rapport
        with open(report_file, 'r', encoding='utf-8') as f:
            self.report = json.load(f)
    
    def verify_sensitive_files(self):
        """Vérifie si les fichiers sensibles sont vraiment accessibles"""
        print("\n🔍 Vérification des fichiers sensibles...")
        print("-" * 50)
        
        files_to_check = [
            '.git/config', '.env', 'wp-config.php', 
            'backup.sql', 'database.sql'
        ]
        
        real_vulnerabilities = []
        false_positives = []
        
        for file in files_to_check:
            if any(file in vuln for vuln in self.report['vulnerabilities']):
                url = urljoin(self.base_url, file)
                try:
                    response = self.session.get(url, timeout=5)
                    
                    # Vérifier si c'est vraiment le fichier attendu
                    if self._is_real_file(file, response):
                        real_vulnerabilities.append(file)
                        print(f"✅ CONFIRMÉ: {file} est accessible!")
                        print(f"   Taille: {len(response.content)} octets")
                        print(f"   Début du contenu: {response.text[:100]}...")
                    else:
                        false_positives.append(file)
                        print(f"❌ Faux positif: {file} (page générique)")
                        
                except Exception as e:
                    false_positives.append(file)
                    print(f"❌ Erreur accès {file}: {str(e)}")
        
        return real_vulnerabilities, false_positives
    
    def _is_real_file(self, filename, response):
        """Détermine si la réponse correspond vraiment au fichier"""
        if response.status_code != 200:
            return False
        
        content = response.text.lower()
        
        # Patterns spécifiques pour chaque type de fichier
        patterns = {
            '.git/config': ['[core]', 'repositoryformatversion'],
            '.env': ['=', 'APP_', 'DB_', '_KEY=', '_SECRET='],
            'wp-config.php': ['<?php', 'DB_NAME', 'DB_USER', 'wp-settings.php'],
            'config.php': ['<?php', '$config', 'database', 'password'],
            '.sql': ['CREATE TABLE', 'INSERT INTO', 'DROP TABLE'],
            'phpinfo.php': ['PHP Version', 'System', 'Build Date'],
            'info.php': ['phpinfo()', 'PHP Version']
        }
        
        # Vérifier les patterns
        for pattern_key, pattern_values in patterns.items():
            if pattern_key in filename:
                return any(pattern in content for pattern in pattern_values)
        
        # Vérifier si c'est une page d'erreur générique
        error_indicators = ['404', 'not found', 'error', 'forbidden', '<!DOCTYPE html>']
        if any(indicator in content for indicator in error_indicators):
            return False
        
        # Si le fichier a une taille significative et n'est pas HTML
        return len(response.content) > 100 and not content.startswith('<!doctype')
    
    def verify_authentication(self):
        """Vérifie les vulnérabilités d'authentification"""
        print("\n🔍 Vérification des authentifications faibles...")
        print("-" * 50)
        
        # Extraire les endpoints uniques
        login_endpoints = set()
        for vuln in self.report['vulnerabilities']:
            if 'Authentification faible' in vuln:
                endpoint = vuln.split(' sur ')[-1]
                login_endpoints.add(endpoint)
        
        print(f"Endpoints de login trouvés: {', '.join(login_endpoints)}")
        
        # Tester un credential sur chaque endpoint
        test_cred = ('admin', 'admin')
        
        for endpoint in login_endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                # Test GET pour voir si l'endpoint existe vraiment
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    # Chercher un formulaire de login
                    if any(indicator in response.text.lower() 
                           for indicator in ['password', 'login', 'username', 'signin']):
                        print(f"✅ Endpoint de login valide: {endpoint}")
                        
                        # Test POST avec credentials
                        data = {
                            'username': test_cred[0],
                            'password': test_cred[1],
                            'user': test_cred[0],
                            'pass': test_cred[1]
                        }
                        
                        post_response = self.session.post(url, data=data, timeout=5)
                        
                        # Vérifier si vraiment connecté
                        if self._check_login_success(post_response):
                            print(f"   🚨 ALERTE: Login réussi avec {test_cred[0]}:{test_cred[1]}")
                        else:
                            print(f"   ✅ Login échoué (bon signe)")
                    else:
                        print(f"❌ Faux positif: {endpoint} n'est pas un vrai formulaire de login")
                else:
                    print(f"❌ Endpoint inexistant: {endpoint} (Code: {response.status_code})")
                    
            except Exception as e:
                print(f"❌ Erreur test {endpoint}: {str(e)}")
    
    def _check_login_success(self, response):
        """Vérifie si le login a réussi"""
        # Indicateurs de succès
        success_indicators = [
            'dashboard', 'welcome', 'logout', 'profile',
            'mon compte', 'déconnexion', 'bienvenue'
        ]
        
        # Indicateurs d'échec
        failure_indicators = [
            'invalid', 'incorrect', 'failed', 'error',
            'invalide', 'incorrect', 'erreur'
        ]
        
        content = response.text.lower()
        url = response.url.lower()
        
        # Vérifier l'URL de redirection
        if any(indicator in url for indicator in success_indicators):
            return True
        
        # Vérifier le contenu
        has_success = any(indicator in content for indicator in success_indicators)
        has_failure = any(indicator in content for indicator in failure_indicators)
        
        return has_success and not has_failure
    
    def verify_cors(self):
        """Vérifie la configuration CORS"""
        print("\n🔍 Vérification CORS...")
        print("-" * 50)
        
        test_origins = ['http://evil.com', 'null', 'https://attacker.com']
        
        for origin in test_origins:
            try:
                headers = {'Origin': origin}
                response = self.session.get(self.base_url, headers=headers, timeout=5)
                
                if 'Access-Control-Allow-Origin' in response.headers:
                    allowed = response.headers['Access-Control-Allow-Origin']
                    if allowed == '*' or allowed == origin:
                        print(f"✅ CONFIRMÉ: CORS accepte {origin}")
                        print(f"   Access-Control-Allow-Origin: {allowed}")
                        
                        # Vérifier aussi les credentials
                        if 'Access-Control-Allow-Credentials' in response.headers:
                            print(f"   🚨 CRITIQUE: Allow-Credentials: {response.headers['Access-Control-Allow-Credentials']}")
                else:
                    print(f"❌ Pas de header CORS pour l'origine {origin}")
                    
            except Exception as e:
                print(f"❌ Erreur test CORS {origin}: {str(e)}")
    
    def generate_summary(self):
        """Génère un résumé des vraies vulnérabilités"""
        print("\n" + "="*60)
        print("RÉSUMÉ DE LA VÉRIFICATION")
        print("="*60)
        
        print(f"\nSite testé: {self.base_url}")
        print(f"Vulnérabilités rapportées: {len(self.report['vulnerabilities'])}")
        
        # Recommandations
        print("\n📋 ACTIONS RECOMMANDÉES:")
        print("1. Vérifiez manuellement chaque vulnérabilité confirmée")
        print("2. Supprimez immédiatement les fichiers sensibles accessibles")
        print("3. Changez tous les mots de passe par défaut")
        print("4. Configurez correctement les headers CORS")
        print("5. Ajoutez les en-têtes de sécurité manquants")
        
        # Sauvegarder le rapport de vérification
        verification_report = {
            'original_report': self.report,
            'verification_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'target_url': self.base_url
        }
        
        filename = f"verification_report_{time.strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(verification_report, f, indent=4, ensure_ascii=False)
        
        print(f"\n💾 Rapport de vérification sauvé: {filename}")


if __name__ == "__main__":
    import sys
    import time
    
    print("🔍 Vérificateur de Résultats de Sécurité")
    print("=" * 50)
    
    # Utiliser le dernier rapport ou demander
    if len(sys.argv) > 1:
        report_file = sys.argv[1]
    else:
        # Chercher le dernier rapport
        import glob
        reports = glob.glob("security_report_*.json")
        if reports:
            report_file = max(reports)  # Le plus récent
            print(f"Utilisation du rapport: {report_file}")
        else:
            report_file = input("Nom du fichier de rapport JSON: ")
    
    # URL cible
    if len(sys.argv) > 2:
        target_url = sys.argv[2]
    else:
        target_url = input("URL du site testé: ")
    
    # Vérification
    verifier = SecurityResultsVerifier(target_url, report_file)
    
    # Tests de vérification
    verifier.verify_sensitive_files()
    verifier.verify_authentication()
    verifier.verify_cors()
    
    # Résumé
    verifier.generate_summary()