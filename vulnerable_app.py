from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

# Page vulnérable pour les tests
@app.route('/')
def home():
    search = request.args.get('search', '')
    # Vulnérabilité XSS intentionnelle
    return f'''
    <h1>Application de Test</h1>
    <form>
        <input name="search" value="{search}">
        <button>Rechercher</button>
    </form>
    <p>Vous avez recherché : {search}</p>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username')
        pwd = request.form.get('password')
        # Vulnérabilité SQL intentionnelle
        query = f"SELECT * FROM users WHERE username='{user}' AND password='{pwd}'"
        # ... code vulnérable pour les tests
    return '<form method="post"><input name="username"><input name="password" type="password"><button>Login</button></form>'

if __name__ == '__main__':
    app.run(debug=True, port=8000)