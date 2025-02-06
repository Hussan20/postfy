from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        return redirect(url_for('login'))  
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        # Validate user credentials
        # Redirect to main menu after login
        return redirect(url_for('main_menu'))
    return render_template('login.html')


@app.route('/main_menu')
def main_menu():
    return render_template('main_menu.html')


if __name__ == '__main__':
    app.run(debug=True)
