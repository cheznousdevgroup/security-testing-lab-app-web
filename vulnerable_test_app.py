#!/usr/bin/env python3
"""
Application web intentionnellement vulnérable pour tester votre scanner
NE JAMAIS DÉPLOYER EN PRODUCTION !
"""

from flask import Flask, request, render_template_string, jsonify, make_response
import sqlite3
import os

app = Flask(__name__)

# Créer une base de données vulnérable
def init_db():
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'password')")
    conn.commit()
    conn.close()

init_db()

# Page d'accueil avec XSS
@app.route('/')
def home():
    search = request.args.get('search', '')
    name = request.args.get('name', '')
    # Vulnérabilité XSS intentionnelle
    return f'''
    <html>
    <head><title>App Vulnérable de Test</title></head>
    <body>
        <h1>Application de Test - Vulnérabilités Intentionnelles</h1>
        <h2>Test XSS</h2>
        <form>
            Recherche: <input name="search" value="{search}">
            <button>Chercher</button>
        </form>
        <p>Résultat: {search}</p>
        
        <h2>Test SQL Injection</h2>
        <form action="/user">
            User ID: <input name="id" value="1">
            <button>Voir utilisateur</button>
        </form>
        
        <p>Bienvenue {name} !</p>
    </body>
    </html>
    '''

# Endpoint avec SQL Injection
@app.route('/user')
def user():
    user_id = request.args.get('id', '1')
    # Vulnérabilité SQL Injection intentionnelle
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"  # DANGEREUX !
    
    try:
        result = c.execute(query).fetchone()
        if result:
            return f"<h1>Utilisateur: {result[1]}</h1><p>ID: {result[0]}</p>"
        else:
            return "<h1>Utilisateur non trouvé</h1>"
    except Exception as e:
        # Affiche l'erreur SQL (mauvaise pratique)
        return f"<h1>Erreur SQL:</h1><pre>{str(e)}</pre>"
    finally:
        conn.close()

# Login vulnérable
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        conn = sqlite3.connect('vulnerable.db')
        c = conn.cursor()
        # Vulnérabilité SQL Injection dans le login
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        
        try:
            result = c.execute(query).fetchone()
            if result:
                return "<h1>Connexion réussie!</h1><p>Bienvenue admin!</p><a href='/admin'>Dashboard</a>"
            else:
                return "<h1>Login échoué</h1><a href='/login'>Réessayer</a>"
        except Exception as e:
            return f"<h1>Erreur:</h1><pre>{str(e)}</pre>"
        finally:
            conn.close()
    
    return '''
    <form method="post">
        <h1>Login</h1>
        Username: <input name="username"><br>
        Password: <input name="password" type="password"><br>
        <button>Se connecter</button>
    </form>
    '''

# Dashboard admin (authentification faible)
@app.route('/admin')
def admin():
    # Pas de vérification d'authentification !
    return '''
    <h1>Dashboard Admin</h1>
    <p>Zone sensible - Normalement protégée!</p>
    <ul>
        <li>Utilisateurs: 1337</li>
        <li>Revenus: $999,999</li>
        <li>Données sensibles...</li>
    </ul>
    '''

# Directory traversal
@app.route('/file')
def file():
    filename = request.args.get('name', 'welcome.txt')
    # Vulnérabilité de traversée de répertoire
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except:
        return "Fichier non trouvé"

# Headers non sécurisés
@app.after_request
def after_request(response):
    # CORS permissif (vulnérabilité)
    origin = request.headers.get('Origin')
    if origin:
        response.headers['Access-Control-Allow-Origin'] = origin
    
    # Pas de headers de sécurité !
    # response.headers['X-Frame-Options'] = 'DENY'  # Commenté exprès
    # response.headers['X-Content-Type-Options'] = 'nosniff'  # Commenté
    
    return response

# Fichiers sensibles simulés
@app.route('/.env')
def env_file():
    # Simule un fichier .env exposé
    return '''APP_NAME=VulnerableApp
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=vulnerable_db
DB_USERNAME=root
DB_PASSWORD=SuperSecret123!
API_KEY=sk-1234567890abcdef
SECRET_KEY=my-super-secret-key-12345'''

@app.route('/.git/config')
def git_config():
    # Simule un .git/config exposé
    return '''[core]
    repositoryformatversion = 0
    filemode = true
[remote "origin"]
    url = https://github.com/company/internal-app.git
    fetch = +refs/heads/*:refs/remotes/origin/*'''

@app.route('/backup.sql')
def backup_sql():
    # Simule un backup SQL exposé
    return '''-- MySQL dump
CREATE TABLE users (id INT, username VARCHAR(50), password VARCHAR(50));
INSERT INTO users VALUES (1, 'admin', 'admin123');
INSERT INTO users VALUES (2, 'root', 'toor');
INSERT INTO users VALUES (3, 'user', 'password');'''

@app.route('/phpinfo.php')
def phpinfo():
    # Simule phpinfo
    return '''<h1>PHP Info</h1>
    <table>
        <tr><td>PHP Version</td><td>7.4.3</td></tr>
        <tr><td>System</td><td>Linux vulnerable-server 5.4.0</td></tr>
        <tr><td>Server API</td><td>Apache 2.0</td></tr>
    </table>'''

# API endpoint vulnérable
@app.route('/api/user/<int:id>')
def api_user(id):
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    result = c.execute(f"SELECT * FROM users WHERE id = {id}").fetchone()
    conn.close()
    
    if result:
        # Expose trop d'informations
        return jsonify({
            'id': result[0],
            'username': result[1],
            'password': result[2],  # Ne jamais exposer les mots de passe !
            'status': 'success'
        })
    return jsonify({'error': 'User not found'}), 404

if __name__ == '__main__':
    print("\n" + "="*60)
    print("APPLICATION VULNÉRABLE DE TEST")
    print("="*60)
    print("⚠️  ATTENTION: Cette application contient des vulnérabilités")
    print("    intentionnelles pour tester votre scanner!")
    print("    NE JAMAIS UTILISER EN PRODUCTION!")
    print("="*60)
    print("\nVulnérabilités incluses:")
    print("- SQL Injection (/user?id=1 et /login)")
    print("- XSS (/search?q=<script>)")
    print("- Directory Traversal (/file?name=../etc/passwd)")
    print("- Fichiers sensibles exposés (/.env, /.git/config, etc.)")
    print("- Authentification faible (admin:admin)")
    print("- CORS mal configuré")
    print("- Headers de sécurité manquants")
    print("\n🚀 Serveur démarré sur http://localhost:5000")
    print("="*60 + "\n")
    
    app.run(debug=True, port=5000)