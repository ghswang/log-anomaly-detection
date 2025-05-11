
# 🔐 Log Anomaly Detection Web App

A full-stack web application for uploading, parsing, analyzing, and viewing Zscaler web proxy logs. It uses Flask (Python) as the backend with machine learning-based anomaly detection, PostgreSQL as the database, and a TypeScript + React frontend for interaction.

## 🛠️ Tech Stack

### Frontend:
- **React (with TypeScript)**
- **HTML/CSS (with custom styling)**

### Backend:
- **Python 3**
- **Flask (REST API)**
- **Flask-CORS & Flask-HTTPAuth (authentication)**
- **SQLAlchemy (ORM)**

### Machine Learning:
- **IsolationForest** from `scikit-learn` for anomaly detection
- **pandas** for data manipulation

### Database:
- **PostgreSQL** (via Docker Compose)

### DevOps & Infra:
- **Docker** & **Docker Compose**
- **dotenv** (.env file for config)

## 👁️ Features

- 🔐 **Basic Authentication** for secure access.
- 📄 **File Upload** for .log and .txt log files.
- 🧠 **Anomaly Detection** using IsolationForest (unsupervised ML).
- 📊 **Live Log Table** with parsed fields, anomaly flags, and reasons.
- 🚹 **Clear Logs** functionality to clean the database and uploaded files.
- 🐘 **PostgreSQL** integration using SQLAlchemy.
- 🐳 **Dockerized** backend and PostgreSQL service with docker-compose.

## 📂 Project Structure

```bash
.
├── app.py                    # Flask backend (entrypoint)
├── docker-compose.yml        # PostgreSQL service definition
├── .env                      # Environment variables
├── requirements.txt          # Python dependencies
├── frontend/                 # Directory for React frontend
├── testing/                  # Test cases and sample logs
├── uploads/                  # Directory where uploaded files are stored
```

## 🚀 Getting Started

### Prerequisites
- **Docker & Docker Compose**
- **Node.js** (for React)
- **Python 3.9+**

### 1. Clone the repository

```bash
git clone https://github.com/ghswang/log-anomaly-detection.git
cd log-anomaly-detection
```

### 2. Backend Setup

#### a. Create a `.env` file in the root:

```ini
POSTGRES_USER=admin
POSTGRES_PASSWORD=secret
POSTGRES_DB=logdb
POSTGRESQL_DATABASE_URL=postgresql://admin:secret@localhost:5432/logdb
```

#### b. Start PostgreSQL with Docker

```bash
docker-compose up -d
```

#### c. Install Python dependencies

```bash
python3 -m venv venv
source ./venv/bin/activate  # or venv\Scriptsctivate on Windows
pip install -r requirements.txt
```

#### d. Run the backend

```bash
python3 app.py
```

The server runs at `http://localhost:5000`.

### 3. Frontend Setup (React + TypeScript)

From the `frontend/` directory:

```bash
cd frontend
npm install
npm start
```

Make sure the backend is running before using the frontend.

## 📅 Usage Guide

### Login

Use the test credentials:

```makefile
Username: test_admin
Password: your_password
```

### Uploading Logs

Only `.txt` and `.log` files are accepted.

**Example log entry**:

```log
"2024-05-10T12:34:56Z" 120.5 "192.168.1.2" ALLOWED GET "example.com" "/home" "Mozilla/5.0" 200 "NONE" "Business"
```

### Anomaly Detection

Flags anomalies based on:

- High latency (`time_elapsed > 5000ms`)
- Blocked requests
- Known threats (`threat_name != NONE`)
- HTTP errors (`status_code >= 400`)

**Uses IsolationForest** when enough entries are available (>= 10).

### Technical Highlights

- **IsolationForest** is used for unsupervised learning. It isolates anomalies faster than regular points and performs well in high-dimensional data. Additionally, IsolationForest assumes that anomalies occur infrequently, which aligns well with the nature of log anomaly detection, where rare events (e.g., threats or errors) are often of interest.
  
- Applied selectively:
  - If the dataset has 10 or more entries, IsolationForest is applied for statistical anomaly detection.
  - If there are fewer than 10 entries, the app switches to rule-based heuristics, which catch threats like blocked requests, known malware, high latency, or HTTP error status.

This hybrid approach ensures reliable anomaly detection on both large and small datasets, leveraging the strengths of both machine learning and rule-based methods.

## 📦 Docker Services

```yaml
# docker-compose.yml
services:
  db:
    image: postgres:15
    ...
    volumes:
      - pgdata:/var/lib/postgresql/data
volumes:
  pgdata:
```

## 🛡️ Security Notes

- Uses **Basic Auth** (username & password in base64 header).
  
For production:
- Replace in-code passwords with hashed credentials in the DB.
- Use **HTTPS** and session/token authentication.

## 📖 Sample Logs

File: `testing/sample_logs_bulk.txt`

```sql
"2024-05-11T12:00:00Z" 150 "10.0.0.1" ALLOWED GET "example.com" "/" "Mozilla/5.0" 200 "NONE" "Business"
"2024-05-11T12:01:00Z" 7500 "10.0.0.2" BLOCKED POST "malicious.com" "/login" "Mozilla/5.0" 403 "MALWARE" "Security"
```

## 📃 Resetting the App

To clear logs and uploaded files:

```bash
curl -X DELETE http://localhost:5000/logs
```

## 👨‍💻 Author

Geoffrey Wang

GitHub: [ghswang](https://github.com/ghswang/log-anomaly-detection)

## 📋 License

This project is open-source and available under the MIT License.
