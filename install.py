#!/usr/bin/env python3
"""
Script d'installation simplifié pour Windows
Installe uniquement les packages qui fonctionnent facilement sur Windows
"""

import subprocess
import sys
import platform

def print_header():
    print("""
    ╔══════════════════════════════════════════════════╗
    ║     Installation Windows - Security Tools        ║
    ╚══════════════════════════════════════════════════╝
    """)

def check_system():
    """Vérifie le système"""
    print(f"🖥️  Système: {platform.system()}")
    print(f"🐍 Python: {sys.version}")
    print(f"📁 Executable: {sys.executable}\n")

def install_packages():
    """Installe les packages compatibles Windows"""
    
    packages = [
        # Core - Toujours nécessaires
        ("requests", "2.31.0", "Requêtes HTTP"),
        ("beautifulsoup4", "4.12.2", "Parsing HTML"),
        ("colorama", "0.4.6", "Couleurs terminal"),
        
        # Brute force et génération
        ("faker", "19.12.0", "Génération de données"),
        ("PySocks", "1.7.1", "Support proxy SOCKS"),
        
        # Utilitaires
        ("python-dateutil", "2.8.2", "Gestion des dates"),
        ("urllib3", "2.0.7", "Utilitaires URL"),
        ("certifi", "2023.11.17", "Certificats SSL"),
    ]
    
    print("📦 Installation des packages...\n")
    
    success = []
    failed = []
    
    for package, version, description in packages:
        print(f"Installation de {package} ({description})...", end=" ")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", f"{package}=={version}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print("✅")
            success.append(package)
        except subprocess.CalledProcessError:
            print("❌")
            failed.append(package)
    
    # Résumé
    print(f"\n✅ Packages installés: {len(success)}")
    print(f"❌ Échecs: {len(failed)}")
    
    if failed:
        print(f"\nPackages en échec: {', '.join(failed)}")
        print("Essayez: pip install", " ".join(failed))
    
    return len(failed) == 0

def test_imports():
    """Teste les imports essentiels"""
    print("\n🧪 Test des imports...")
    
    imports = [
        "requests",
        "bs4",
        "colorama",
        "faker",
        "socks",
        "dateutil"
    ]
    
    all_ok = True
    for module in imports:
        try:
            __import__(module)
            print(f"  ✅ {module}")
        except ImportError:
            print(f"  ❌ {module}")
            all_ok = False
    
    return all_ok

def create_test_script():
    """Crée un script de test simple"""
    test_content = '''#!/usr/bin/env python3
"""Script de test rapide"""
import requests
from bs4 import BeautifulSoup
from colorama import init, Fore

init()  # Initialiser colorama pour Windows

def test_basic_security(url):
    """Test de sécurité basique"""
    print(Fore.CYAN + f"\\n🔍 Test de {url}")
    
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
        
        print(Fore.CYAN + "\\n🔒 Headers de sécurité:")
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
    
    url = input(Fore.GREEN + "\\nEntrez l'URL à tester: ")
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    test_basic_security(url)
    
    print(Fore.YELLOW + "\\n✅ Test terminé!")
'''
    
    with open('test_security_windows.py', 'w', encoding='utf-8') as f:
        f.write(test_content)
    
    print("\n📝 Script de test créé: test_security_windows.py")

def main():
    """Fonction principale"""
    print_header()
    check_system()
    
    # Mettre à jour pip
    print("📦 Mise à jour de pip...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
    
    # Installer les packages
    if install_packages():
        print("\n✅ Installation réussie!")
    else:
        print("\n⚠️  Certains packages n'ont pas pu être installés")
    
    # Tester les imports
    if test_imports():
        print("\n✅ Tous les modules sont disponibles!")
        create_test_script()
        print("\n🚀 Vous pouvez maintenant utiliser les outils de sécurité!")
        print("   Essayez: python test_security_windows.py")
    else:
        print("\n⚠️  Certains modules sont manquants")
        print("   Les fonctionnalités de base devraient fonctionner")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Installation annulée")
    except Exception as e:
        print(f"\n❌ Erreur: {e}")
    
    input("\nAppuyez sur Entrée pour fermer...")