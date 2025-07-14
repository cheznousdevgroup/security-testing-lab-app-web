#!/usr/bin/env python3
"""
Script de démarrage rapide pour les tests de sécurité
"""

from security_tester import WebSecurityTester
import sys

def main():
    print("╔══════════════════════════════════════════╗")
    print("║   Lab de Test de Sécurité - Quick Start  ║")
    print("╚══════════════════════════════════════════╝")
    
    # Demander l'URL si non fournie
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = input("\n🎯 Entrez l'URL à tester (ex: http://localhost:8000): ").strip()
    
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    print(f"\n✅ URL cible : {target_url}")
    
    # Confirmation
    confirm = input("\n⚠️  Confirmez que vous avez l'autorisation de tester cette URL (oui/non): ")
    if confirm.lower() not in ['oui', 'o', 'yes', 'y']:
        print("❌ Test annulé.")
        return
    
    # Menu de sélection
    print("\n📋 Sélectionnez les tests à effectuer :")
    print("1. Tous les tests (complet)")
    print("2. Tests rapides (en-têtes et fichiers)")
    print("3. Test d'injection SQL uniquement")
    print("4. Test XSS uniquement")
    print("5. Test d'authentification uniquement")
    
    choice = input("\nVotre choix (1-5): ").strip()
    
    # Créer le testeur
    tester = WebSecurityTester(target_url)
    
    print("\n🔍 Démarrage des tests...\n")
    
    # Exécuter les tests selon le choix
    if choice == '1':
        tester.run_all_tests()
    elif choice == '2':
        tester.test_headers_security()
        tester.test_sensitive_files()
    elif choice == '3':
        tester.test_sql_injection()
    elif choice == '4':
        tester.test_xss()
    elif choice == '5':
        tester.test_weak_authentication()
    else:
        print("❌ Choix invalide")
        return
    
    # Générer le rapport
    tester.generate_report()
    
    print("\n✅ Tests terminés !")
    print("📄 Consultez le rapport JSON généré pour plus de détails.")

if __name__ == "__main__":
    main()