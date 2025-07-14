#!/usr/bin/env python3
"""Script de test rapide"""
import requests
from bs4 import BeautifulSoup
from colorama import init, Fore

init()  # Initialiser colorama pour Windows

def test_basic_security(url):
    """Test de sécurité basique"""
    print(Fore.CYAN + f"\n🔍 Test de {url}")
    
    try:
        # Test de connexion
        response = requests.get(url, timeout=5, verify=False)
        print(Fore.GREEN + f"✅ Connexion OK - Status: {response.status_code}")
        
        # Parser HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.find('title')
        if title:
            print(Fore.YELLOW + f"📄 Titre: {title.text.strip()}")
        
        # Vérifier les headers de sécurité
        headers_to_check = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Strict-Transport-Security',
            'Content-Security-Policy'
        ]
        
        print(Fore.CYAN + "\n🔒 Headers de sécurité:")
        for header in headers_to_check:
            if header in response.headers:
                print(Fore.GREEN + f"  ✅ {header}: {response.headers[header]}")
            else:
                print(Fore.RED + f"  ❌ {header}: Manquant")
                
    except Exception as e:
        print(Fore.RED + f"❌ Erreur: {e}")

if __name__ == "__main__":
    print(Fore.CYAN + "Test de sécurité simple pour Windows")
    print(Fore.CYAN + "=" * 40)
    
    url = input(Fore.GREEN + "\nEntrez l'URL à tester: ")
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    test_basic_security(url)
    
    print(Fore.YELLOW + "\n✅ Test terminé!")
