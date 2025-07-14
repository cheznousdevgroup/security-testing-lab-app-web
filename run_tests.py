#!/usr/bin/env python3
import sys
import argparse
from security_tester import WebSecurityTester

def main():
    parser = argparse.ArgumentParser(description='Lab de test de sécurité web')
    parser.add_argument('url', help='URL cible à tester')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout des requêtes')
    parser.add_argument('--quick', action='store_true', help='Tests rapides uniquement')
    
    args = parser.parse_args()
    
    print(f"🔍 Démarrage des tests sur {args.url}")
    
    tester = WebSecurityTester(args.url, timeout=args.timeout)
    
    if args.quick:
        # Tests rapides seulement
        tester.test_headers_security()
        tester.test_sensitive_files()
    else:
        # Tous les tests
        tester.run_all_tests()
    
    tester.generate_report()

if __name__ == "__main__":
    main()