from flask import Flask, request, jsonify
import os
import subprocess

app = Flask(__name__)

# Hard-coded password
PASSWORD = "supersecretpassword"

@app.route('/')
def hello():
    name = request.args.get('name', 'World')
    if not name.isalnum():
        return jsonify({"error": "Invalid name"}), 400
    return f"Hello, {name}!"

# Command injection vulnerability
@app.route('/ping')
def ping():
    ip = request.args.get('ip')
    # Unsafe command execution
    result = subprocess.check_output(f"ping -c 1 {ip}", shell=True)
    return result

# Insecure use of eval
@app.route('/calculate')
def calculate():
    expression = request.args.get('expr')
    # Dangerous use of eval
    result = eval(expression)
    return str(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
