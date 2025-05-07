import ast
from flask import Flask, request, jsonify
import os
import subprocess

app = Flask(__name__)

# Hard-coded password CHANGED TO ENVIRONMENT VARIABLE 
PASSWORD = os.environ.get("APP_PASSWORD")

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
    # Dangerous use of eval FIXED 
	try:
    		result = ast.literal_eval(expression)
	except Exception as e:
    		return jsonify({"error": "Invalid expression"}), 400
    return str(result)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)

