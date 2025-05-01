from flask import Flask, request, render_template_string
import os
import logging

app = Flask(__name__)

# Setup logging
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

logging.basicConfig(
    filename=os.path.join(log_dir, 'flaskapp.log'),
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# Hardcoded (fake) credentials
CORRECT_USERNAME = "admin"
CORRECT_PASSWORD = "123456"

# HTML template with placeholder for error message
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Legitimate NVR</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(#1c1c1c, #2c2c2c);
            color: #fff;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-box {
            background: #1b1b1b;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 0 15px rgba(0, 0, 0, 0.5);
            width: 350px;
        }
        .login-box h2 {
            margin-bottom: 20px;
            text-align: center;
            color: #e60012;
        }
        .error-message {
            color: red;
            text-align: center;
            margin-bottom: 15px;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            background: #333;
            border: 1px solid #444;
            color: #fff;
            border-radius: 5px;
        }
        button {
            width:100%;
            padding: 10px;
            background-color: #e60012;
            border: none;
            color: #fff;
            font-weight: bold;
            border-radius: 5px;
            cursor: pointer;
        }
        button:hover {
            background-color: #ff1a25;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Legitimate NVR</h2>
        {% if error %}
            <div class="error-message">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        client_ip = request.remote_addr

        # Always log the attempt
        logging.info(f"Login attempt from {client_ip} - Username: '{username}' Password: '{password}'")

        # Fake check credentials
        if username == CORRECT_USERNAME and password == CORRECT_PASSWORD:
            return "<h2 style='color:#fff; background:#111; padding:20px;'>Login successful!</h2>"
        else:
            error = "Invalid username or password"

    return render_template_string(HTML_TEMPLATE, error=error)

@app.route('/admin')
def admin():
    return "<h2 style='color:#fff; background:#111; padding:20px;'>Admin Page</h2>"

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80)
