# Flask for web server, request handling
from flask import Flask, request, jsonify
# For safely handling uploaded filenames
from werkzeug.utils import secure_filename
# SQLAlchemy for database ORM
from flask_sqlalchemy import SQLAlchemy
# IsolationForest for unsupervised anomaly detection
from sklearn.ensemble import IsolationForest
# Standard modules for file paths, parsing
import os
import shlex
import datetime
from decimal import Decimal
# pandas for numerical feature processing
import pandas as pd
from flask_cors import CORS
from dotenv import load_dotenv
# For user login (basic authentication)
from flask_httpauth import HTTPBasicAuth

# Load environment variables from .env file
load_dotenv()
# Initialize HTTPBasicAuth for basic authentication
auth = HTTPBasicAuth()
# Initialize Flask app
app = Flask(__name__)
# Enable CORS for all routes
CORS(app)

# ---------------------- USER AUTHENTICATION --------------------

# Example user database for authentication
users = {
    "test_admin": "your_password",  # Example: username : password (use hashed passwords in real apps)
}

# Basic Authentication verification function
@auth.verify_password
def verify_password(username, password):
    if username in users and users[username] == password:
        return username
    return None

# ---------------------- DATABASE CONFIG -------------------------

# PostgreSQL database URL
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("POSTGRESQL_DATABASE_URL")
# Disable event notifications for performance
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Initialize SQLAlchemy extension
db = SQLAlchemy(app)

# Directory for storing uploaded log files
UPLOAD_FOLDER = './uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Create folder if it does not already exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Define the expected columns in ZScaler logs (whitespace-separated)
ZSCALER_FIELDS = [
    "time_received", "time_elapsed", "src_ip", "action", "request_method",
    "uri_host", "uri_path", "user_agent", "status_code", "threat_name", "url_category"
]

# ---------------------- DATABASE MODEL --------------------------

# Define table schema for storing log entries
class LogEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time_received = db.Column(db.String)
    time_elapsed = db.Column(db.Float)
    src_ip = db.Column(db.String)
    action = db.Column(db.String)
    request_method = db.Column(db.String)
    uri_host = db.Column(db.String)
    uri_path = db.Column(db.String)
    user_agent = db.Column(db.String)
    status_code = db.Column(db.Integer)
    threat_name = db.Column(db.String)
    url_category = db.Column(db.String)
    is_anomaly = db.Column(db.Boolean)
    confidence_score = db.Column(db.Float)
    anomaly_reason = db.Column(db.Text)

# ---------------------- ROOT ROUTE ------------------------------
# Simple route for the root URL
@app.route('/')
def home():
    return "Welcome to the Log Parser API!"

# ---------------------- ROUTE: Login ----------------------------

# GET endpoint for user login (basic auth required)
@app.route('/login', methods=['GET'])
@auth.login_required # Ensure that the user is logged in
def login():
    return jsonify({"message": f"Welcome, {auth.current_user()}!"})

# ---------------------- ROUTE: Upload Logs ----------------------

# POST endpoint to upload and analyze a log file
@app.route('/upload', methods=['POST'])
def upload_log_file():
    # Check if the request contains a file
    if 'file' not in request.files:
        # Return an error response if no file was included
        return jsonify({'error': 'No file part in the request'}), 400

    # Retrieve the file from the request
    file = request.files['file']

    # Return an error response if the user submitted a file input but didn't select a file
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Sanitize the filename to avoid directory traversal attacks
    filename = secure_filename(file.filename)

    # Save the uploaded file to a local 'uploads' directory
    filepath = os.path.join('uploads', filename)
    file.save(filepath)

    # Try parsing the saved log file
    try:
        parsed_logs = parse_log_with_quotes(filepath)  # Should return a list of parsed log dicts
    except Exception as e:
        # If there's an error while parsing, return it as a 500 error
        return jsonify({'error': f'Error parsing log file: {str(e)}'}), 500

    # Run an analysis on the parsed logs (e.g., flag anomalies, summarize data, etc.)
    try:
        analyzed_logs = detect_anomalies(parsed_logs)
    except Exception as e:
        # Catch any error during log analysis
        return jsonify({'error': f'Error analyzing log file: {str(e)}'}), 500

    # Ensure the final data is safe to be returned as JSON
    #
    # Flask's jsonify can only handle basic types: str, int, float, bool, None, list, dict
    def serialize_entry(entry):
        # Converts all fields in a single log entry to JSON-safe types
        # Handles common cases like datetime, Decimal, and custom objects.
        return {
            k: (
                v.isoformat() if isinstance(v, (datetime.date, datetime.datetime)) else  # Convert dates to string
                float(v) if isinstance(v, Decimal) else                                   # Convert Decimal to float
                str(v) if not isinstance(v, (str, int, float, bool, type(None))) else     # Fallback: string
                v  # Otherwise, leave it unchanged (already JSON-safe)
            )
            for k, v in entry.items()
        }

    # Serialize every log entry in the result list
    try:
        serializable_logs = [serialize_entry(log) for log in analyzed_logs]

        # Return the logs as a JSON response
        return jsonify({'parsed': serializable_logs}), 200
    except Exception as e:
        # If there's any unexpected object that cannot be serialized
        return jsonify({'error': f'Failed to serialize logs: {str(e)}'}), 500

# ---------------------- ROUTE: View Logs ------------------------

# GET endpoint to fetch latest 100 logs from DB
@app.route('/logs', methods=['GET'])
def get_logs():
    logs = LogEntry.query.order_by(LogEntry.id.desc()).limit(100).all()
    return jsonify([{
        'id': log.id,
        'time_received': log.time_received,
        'src_ip': log.src_ip,
        'action': log.action,
        'status_code': log.status_code,
        'is_anomaly': log.is_anomaly,
        'confidence_score': log.confidence_score,
        'anomaly_reason': log.anomaly_reason
    } for log in logs])

# ---------------------- ROUTE: Clear Logs ------------------------

# DELETE endpoint to clear all logs from DB and local uploads directory
@app.route('/logs', methods=['DELETE'])
def clear_logs():
    try:
        num_deleted = db.session.query(LogEntry).delete()
        db.session.commit()

       # Path to the uploads directory
        uploads_dir = app.config['UPLOAD_FOLDER']

        # Delete all files in the uploads directory
        for filename in os.listdir(uploads_dir):
            file_path = os.path.join(uploads_dir, filename)
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
            except Exception as e:
                print(f"Failed to delete {file_path}: {str(e)}")

        return jsonify({'message': f'Deleted {num_deleted} log entries and their corresponding files.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete logs: {str(e)}'}), 500

# ---------------------- LOG PARSER ------------------------------

# Parses a whitespace-separated file using `shlex` to support quoted fields
def parse_log_with_quotes(filepath):
    entries = []
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

     # Try parsing the first line
    try:
        first_line_fields = shlex.split(lines[0].strip())
    except ValueError:
        first_line_fields = []

    # Check if the first line matches the known field headers
    is_header = first_line_fields == ZSCALER_FIELDS

    # Skip the header if detected
    lines_to_parse = lines[1:] if is_header else lines

    for line in lines_to_parse:
        try:
            parts = shlex.split(line.strip())
        except ValueError:
            continue  # Skip lines that can't be parsed

        if len(parts) != len(ZSCALER_FIELDS):
            continue

        entry = dict(zip(ZSCALER_FIELDS, parts))
        entries.append(entry)

    return entries

# ---------------------- ANOMALY DETECTION -----------------------

# Detects anomalies using IsolationForest (unsupervised ML algo designed for anomaly detection)
def detect_anomalies(log_entries):
    # Base case: return early if the input is empty
    if not log_entries:
        return []

    # Convert log entries to DataFrame
    df = pd.DataFrame(log_entries)

    # Ensure numerical features are converted properly
    df['time_elapsed'] = pd.to_numeric(df['time_elapsed'], errors='coerce')
    df['status_code'] = pd.to_numeric(df['status_code'], errors='coerce')

    # Use only numerical fields for IsolationForest input
    features = df[['time_elapsed', 'status_code']].fillna(-1)

    # Decide whether to use IsolationForest based on the dataset size
    use_model = len(log_entries) >= 10  # IsolationForest needs a reasonable number of samples

    if use_model:
        # Initialize IsolationForest with 10% contamination (expected anomaly proportion)
        model = IsolationForest(contamination=0.1, random_state=42)
        
        # Fit the model and get predictions: -1 = anomaly, 1 = normal
        preds = model.fit_predict(features)
        
        # Get anomaly scores (the lower the score, the more anomalous)
        scores = model.decision_function(features)
    else:
        # Fallback: mark all entries as normal and assign zero anomaly score
        preds = [1] * len(log_entries)
        scores = [0.0] * len(log_entries)

    # Final result list that will be returned to the client
    results = []

    # Iterate over all log entries to attach anomaly info and save to DB
    for i, entry in enumerate(log_entries):
        # Determine if this entry is an anomaly (based on model prediction)
        is_anomaly = preds[i] == -1

        # Get the anomaly score (used only when model is available)
        score = float(scores[i]) if use_model else 0.0 # Otherwise, default to 0

        # Placeholder for human-readable explanation of anomaly
        reason = None

        # Collect heuristic (rule-based) anomaly reasons for this log entry
        heuristic_reasons = []

        # Example heuristic: the request was blocked
        if entry['action'] == 'BLOCKED':
            heuristic_reasons.append("Blocked request")

        # Example heuristic: a known threat is detected in the log
        if entry['threat_name'] != "NONE":
            heuristic_reasons.append("Threat detected: " + entry['threat_name'])

        # Example heuristic: very slow response (e.g. long latency)
        if float(entry.get('time_elapsed', 0)) > 5000:
            heuristic_reasons.append("Unusually long response time")

        # Example heuristic: HTTP error status code (e.g. 403, 500)
        if int(entry.get('status_code', 200)) >= 400:
            heuristic_reasons.append("HTTP error status")

        # If not using the model but heuristics find something, mark as an anomaly
        if not use_model and heuristic_reasons:
            is_anomaly = True
            score = 0.99  # Use a high confidence score for heuristic anomalies
            reason = "; ".join(heuristic_reasons) # Combine the reasons into string
        elif is_anomaly:
            # If model flags as anomaly, use heuristic reasons if available
            reason = "; ".join(heuristic_reasons) if heuristic_reasons else "Statistically rare combination of values"

        # Construct a SQLAlchemy object instance for this log, including anomaly metadata
        log = LogEntry(
            time_received=entry['time_received'],
            time_elapsed=float(entry['time_elapsed']),
            src_ip=entry['src_ip'],
            action=entry['action'],
            request_method=entry['request_method'],
            uri_host=entry['uri_host'],
            uri_path=entry['uri_path'],
            user_agent=entry['user_agent'],
            status_code=int(entry['status_code']),
            threat_name=entry['threat_name'],
            url_category=entry['url_category'],
            is_anomaly=is_anomaly,
            confidence_score=round(abs(score), 3),
            anomaly_reason=reason
        )
        db.session.add(log)  # Stage log entry for insertion into the database

        # Prepare the log entry as a JSON-serializable dictionary for frontend
        result = dict(entry)
        result['is_anomaly'] = is_anomaly
        result['confidence_score'] = round(abs(score), 3)
        if is_anomaly:
            result['anomaly_reason'] = reason
        results.append(result)  # Add to the final results list

    # Commit all new entries to the database in a single transaction
    db.session.commit()

    # Return the enriched results (with anomaly info) to be sent back to the client
    return results

# ---------------------- DB Init + Server Start ------------------

# Create DB tables if they don't already exist
with app.app_context():
    db.create_all()

# Run Flask server in debug mode
if __name__ == '__main__':
    app.run(debug=True)
