# Deployment and Operational Guidance

This document provides comprehensive guidance for deploying, operating, and maintaining the Web3 Security Auditing AI System in production environments.

## Table of Contents

- [System Requirements](#system-requirements)
- [Installation and Setup](#installation-and-setup)
- [Configuration Management](#configuration-management)
- [Deployment Strategies](#deployment-strategies)
- [Monitoring and Observability](#monitoring-and-observability)
- [Performance Tuning](#performance-tuning)
- [Backup and Recovery](#backup-and-recovery)
- [Security Hardening](#security-hardening)
- [Maintenance Procedures](#maintenance-procedures)
- [Troubleshooting Production Issues](#troubleshooting-production-issues)
- [Scaling and High Availability](#scaling-and-high-availability)

---

## System Requirements

### Hardware Requirements

#### Minimum Requirements (Development/Testing)
- **CPU**: 4 cores (2.5 GHz base frequency)
- **RAM**: 8 GB
- **Storage**: 50 GB SSD
- **Network**: 10 Mbps stable connection

#### Recommended Requirements (Production - Small Scale)
- **CPU**: 8 cores (3.0 GHz+)
- **RAM**: 16 GB
- **Storage**: 100 GB SSD + 500 GB HDD for archives
- **Network**: 100 Mbps dedicated connection
- **GPU**: Optional, NVIDIA GPU with 4GB+ VRAM for ML acceleration

#### Enterprise Requirements (Production - Large Scale)
- **CPU**: 16+ cores (3.5 GHz+)
- **RAM**: 64 GB+
- **Storage**: 500 GB SSD + 2TB+ HDD/NAS for archives
- **Network**: 1 Gbps dedicated connection
- **GPU**: NVIDIA GPU with 8GB+ VRAM (recommended for ML features)

### Software Requirements

#### Operating System
- **Linux**: Ubuntu 20.04+, CentOS 8+, RHEL 8+
- **macOS**: 12.0+ (for development)
- **Windows**: Windows 10/11 with WSL2 (for development)

#### Runtime Dependencies
- **Python**: 3.12.0+
- **Node.js**: 18.0+ (for some analysis tools)
- **Docker**: 24.0+ (for containerized tools)
- **Database**: PostgreSQL 13+ or MongoDB 5+

#### External Tools
- **Slither**: 0.10.0+
- **Mythril**: Latest stable
- **Solc**: 0.8.19+
- **Git**: 2.30+

### Network Requirements

#### Inbound Connections
- **HTTPS**: Port 443 (API and web interface)
- **SSH**: Port 22 (administrative access)
- **Database**: Port 5432 (PostgreSQL) or 27017 (MongoDB)

#### Outbound Connections
- **Blockchain Nodes**: Various ports for Ethereum, Polygon, etc.
- **AI APIs**: OpenAI, Anthropic, etc. (if using cloud models)
- **Security Databases**: CVE databases, threat intelligence feeds
- **Update Servers**: For tool and system updates

---

## Installation and Setup

### Automated Installation

#### Using Ansible (Recommended for Production)

```yaml
# inventory.ini
[audit_servers]
audit01 ansible_host=192.168.1.10
audit02 ansible_host=192.168.1.11

[databases]
db01 ansible_host=192.168.1.20

# playbook.yml
---
- name: Deploy Web3 Security Audit System
  hosts: audit_servers
  become: yes
  vars:
    web3_audit_version: "0.1.0"
    db_host: "{{ groups['databases'][0] }}"

  tasks:
    - name: Install system dependencies
      apt:
        name:
          - python3.12
          - python3.12-venv
          - postgresql-client
          - docker.io
          - git
        state: present
        update_cache: yes

    - name: Create application user
      user:
        name: web3audit
        system: yes
        shell: /bin/bash
        home: /opt/web3audit

    - name: Clone repository
      git:
        repo: https://github.com/your-org/web3-security-ai.git
        dest: /opt/web3audit/app
        version: "{{ web3_audit_version }}"
      become_user: web3audit

    - name: Create virtual environment
      command: python3.12 -m venv /opt/web3audit/venv
      become_user: web3audit

    - name: Install Python dependencies
      pip:
        requirements: /opt/web3audit/app/requirements.txt
        virtualenv: /opt/web3audit/venv
      become_user: web3audit

    - name: Install analysis tools
      command: /opt/web3audit/venv/bin/python -m web3_security_ai.tools.install_tools
      become_user: web3audit

    - name: Configure environment
      template:
        src: templates/env.j2
        dest: /opt/web3audit/.env
        owner: web3audit
        mode: '0600'

    - name: Create systemd service
      template:
        src: templates/web3audit.service.j2
        dest: /etc/systemd/system/web3audit.service

    - name: Enable and start service
      systemd:
        name: web3audit
        enabled: yes
        state: started
        daemon_reload: yes
```

#### Docker Compose Deployment

```yaml
# docker-compose.yml
version: '3.8'

services:
  web3audit:
    image: web3-security-ai:latest
    build:
      context: .
      dockerfile: Dockerfile.prod
    environment:
      - WEB3_AUDIT_ENV=production
      - DB_HOST=db
      - REDIS_HOST=redis
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    depends_on:
      - db
      - redis
    restart: unless-stopped

  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=web3audit
      - POSTGRES_USER=web3audit
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - db_data:/var/lib/postgresql/data
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    restart: unless-stopped

volumes:
  db_data:
  redis_data:
```

### Manual Installation

#### Step-by-Step Setup

1. **Prepare System**
   ```bash
   # Update system
   sudo apt update && sudo apt upgrade -y

   # Install dependencies
   sudo apt install -y python3.12 python3.12-venv postgresql-client docker.io git

   # Install Node.js (for some tools)
   curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
   sudo apt-get install -y nodejs
   ```

2. **Create Application User**
   ```bash
   sudo useradd -r -s /bin/bash -m -d /opt/web3audit web3audit
   sudo usermod -aG docker web3audit
   ```

3. **Clone and Install**
   ```bash
   sudo -u web3audit bash << 'EOF'
   cd /opt/web3audit

   # Clone repository
   git clone https://github.com/your-org/web3-security-ai.git app
   cd app

   # Create virtual environment
   python3.12 -m venv ../venv
   source ../venv/bin/activate

   # Install dependencies
   pip install -r requirements.txt

   # Install analysis tools
   python -m web3_security_ai.tools.install_tools
   EOF
   ```

4. **Configure Environment**
   ```bash
   sudo -u web3audit tee /opt/web3audit/.env > /dev/null << EOF
   # Production Configuration
   WEB3_AUDIT_ENV=production
   WEB3_AUDIT_LOG_LEVEL=INFO
   DB_HOST=localhost
   DB_NAME=web3audit
   DB_USER=web3audit
   DB_PASSWORD=secure_password_here
   REDIS_HOST=localhost
   SECRET_KEY=$(openssl rand -hex 32)
   EOF
   ```

5. **Setup Database**
   ```bash
   # Create database
   sudo -u postgres createdb web3audit
   sudo -u postgres createuser web3audit
   sudo -u postgres psql -c "ALTER USER web3audit PASSWORD 'secure_password_here';"
   sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE web3audit TO web3audit;"

   # Run migrations
   sudo -u web3audit bash -c "cd /opt/web3audit/app && source ../venv/bin/activate && python manage.py migrate"
   ```

6. **Configure Systemd Service**
   ```bash
   sudo tee /etc/systemd/system/web3audit.service > /dev/null << EOF
   [Unit]
   Description=Web3 Security Auditing AI System
   After=network.target postgresql.service redis-server.service

   [Service]
   Type=simple
   User=web3audit
   Group=web3audit
   WorkingDirectory=/opt/web3audit/app
   Environment=PATH=/opt/web3audit/venv/bin
   ExecStart=/opt/web3audit/venv/bin/python -m web3_security_ai.cli serve
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   EOF

   sudo systemctl daemon-reload
   sudo systemctl enable web3audit
   sudo systemctl start web3audit
   ```

---

## Configuration Management

### Configuration Hierarchy

1. **System Defaults**: Built-in default values
2. **Environment Variables**: Override defaults
3. **Configuration Files**: YAML/JSON files
4. **Runtime Overrides**: API/database overrides

### Configuration Files

#### Main Configuration File

```yaml
# config/production.yaml
system:
  environment: production
  log_level: INFO
  secret_key: ${SECRET_KEY}
  debug: false

database:
  host: ${DB_HOST}
  port: 5432
  name: ${DB_NAME}
  user: ${DB_USER}
  password: ${DB_PASSWORD}
  ssl_mode: require

redis:
  host: ${REDIS_HOST}
  port: 6379
  db: 0
  password: ${REDIS_PASSWORD}

audit:
  max_concurrent_audits: 10
  default_timeout: 1800
  max_file_size: 10485760  # 10MB
  allowed_file_types: [".sol", ".vy", ".json"]

agents:
  orchestrator:
    max_workers: 4
    queue_size: 100
  web3_audit:
    deep_analysis: true
    parallel_processing: true
  ml_engine:
    model_cache_size: 100
    prediction_timeout: 300

tools:
  slither:
    version: "0.10.0"
    timeout: 300
    config:
      exclude_dependencies: true
      detectors: ["reentrancy", "unchecked-lowlevel-call"]
  mythril:
    version: "latest"
    timeout: 600
    config:
      max_depth: 12

reporting:
  formats: ["json", "pdf", "html"]
  storage:
    type: filesystem
    path: /opt/web3audit/reports
    retention_days: 365
  email:
    enabled: true
    smtp_server: smtp.company.com
    smtp_port: 587
    from_address: audits@company.com

security:
  api_keys_required: true
  rate_limiting:
    enabled: true
    requests_per_minute: 60
  audit_trail:
    enabled: true
    log_api_calls: true

monitoring:
  prometheus:
    enabled: true
    port: 9090
  health_checks:
    enabled: true
    interval: 30
```

### Environment Variables

#### Required Variables

```bash
# Database
DB_HOST=localhost
DB_NAME=web3audit
DB_USER=web3audit
DB_PASSWORD=secure_password

# Security
SECRET_KEY=your-secret-key-here

# External Services
REDIS_HOST=localhost
SMTP_SERVER=smtp.company.com
```

#### Optional Variables

```bash
# Performance Tuning
WEB3_AUDIT_MAX_WORKERS=4
WEB3_AUDIT_MEMORY_LIMIT=4GB

# Feature Flags
WEB3_AUDIT_ML_ENABLED=true
WEB3_AUDIT_ADVANCED_REPORTING=true

# External APIs
OPENAI_API_KEY=sk-your-key
ANTHROPIC_API_KEY=your-key
```

### Configuration Validation

```python
from web3_security_ai.config import ConfigValidator, ConfigLoader

class ProductionConfigManager:
    """Manages production configuration with validation."""

    def __init__(self):
        self.validator = ConfigValidator()
        self.loader = ConfigLoader()

    def load_and_validate_config(self, config_path: str) -> dict:
        """Load and validate configuration."""
        # Load configuration
        config = self.loader.load_from_file(config_path)

        # Validate configuration
        validation_errors = self.validator.validate(config)

        if validation_errors:
            raise ConfigurationError(f"Invalid configuration: {validation_errors}")

        # Apply environment variable overrides
        config = self._apply_env_overrides(config)

        # Validate external dependencies
        self._validate_dependencies(config)

        return config

    def _apply_env_overrides(self, config: dict) -> dict:
        """Apply environment variable overrides."""
        import os

        # Database overrides
        if os.getenv('DB_HOST'):
            config['database']['host'] = os.getenv('DB_HOST')

        # Security overrides
        if os.getenv('SECRET_KEY'):
            config['system']['secret_key'] = os.getenv('SECRET_KEY')

        return config

    def _validate_dependencies(self, config: dict):
        """Validate external dependencies."""
        # Check database connectivity
        self._check_database_connection(config['database'])

        # Check Redis connectivity
        self._check_redis_connection(config.get('redis'))

        # Check tool availability
        self._check_tools_availability(config.get('tools', {}))
```

---

## Deployment Strategies

### Blue-Green Deployment

```bash
#!/bin/bash
# Blue-green deployment script

BLUE_PORT=8000
GREEN_PORT=8001
CURRENT_PORT=$BLUE_PORT

# Deploy to green environment
echo "Deploying to green environment (port $GREEN_PORT)..."

# Build new version
docker build -t web3audit:new .

# Start green environment
docker run -d --name web3audit-green \
  -p $GREEN_PORT:8000 \
  -e WEB3_AUDIT_ENV=production \
  web3audit:new

# Wait for health check
echo "Waiting for green environment to be healthy..."
for i in {1..30}; do
  if curl -f http://localhost:$GREEN_PORT/health; then
    echo "Green environment is healthy"
    break
  fi
  sleep 10
done

# Switch traffic (using nginx or load balancer)
echo "Switching traffic to green environment..."
sudo sed -i "s/$CURRENT_PORT/$GREEN_PORT/" /etc/nginx/sites-available/web3audit
sudo systemctl reload nginx

# Wait for traffic to drain
sleep 30

# Stop blue environment
echo "Stopping blue environment..."
docker stop web3audit-blue
docker rm web3audit-blue

# Rename green to blue for next deployment
docker tag web3audit:new web3audit:current
docker rmi web3audit:old 2>/dev/null || true
docker tag web3audit:current web3audit:old

echo "Deployment completed successfully"
```

### Rolling Deployment

```bash
#!/bin/bash
# Rolling deployment script

REPLICAS=3
IMAGE_TAG=${1:-latest}

echo "Starting rolling deployment with $REPLICAS replicas..."

# Update each replica one by one
for i in $(seq 1 $REPLICAS); do
  echo "Updating replica $i..."

  # Stop old container
  docker stop "web3audit-replica-$i" || true
  docker rm "web3audit-replica-$i" || true

  # Start new container
  docker run -d --name "web3audit-replica-$i" \
    --network web3audit-network \
    -e WEB3_AUDIT_ENV=production \
    "web3audit:$IMAGE_TAG"

  # Wait for health check
  for j in {1..10}; do
    if docker exec "web3audit-replica-$i" curl -f http://localhost:8000/health; then
      echo "Replica $i is healthy"
      break
    fi
    sleep 5
  done

  echo "Replica $i updated successfully"
done

echo "Rolling deployment completed"
```

### Canary Deployment

```bash
#!/bin/bash
# Canary deployment script

CANARY_PERCENTAGE=10
TOTAL_REQUESTS=1000
CANARY_REQUESTS=$((TOTAL_REQUESTS * CANARY_PERCENTAGE / 100))

echo "Starting canary deployment ($CANARY_PERCENTAGE% traffic)..."

# Deploy canary version
docker run -d --name web3audit-canary \
  -p 8001:8000 \
  -e WEB3_AUDIT_ENV=production \
  web3audit:new

# Configure load balancer for canary routing
cat > /etc/nginx/sites-available/web3audit-canary << EOF
upstream backend {
    ip_hash;
    server localhost:8000 weight=9;  # 90% to stable
    server localhost:8001 weight=1;  # 10% to canary
}

server {
    listen 80;
    server_name audit.company.com;

    location / {
        proxy_pass http://backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/web3audit-canary /etc/nginx/sites-enabled/
sudo systemctl reload nginx

echo "Canary deployment active. Monitoring for $CANARY_REQUESTS requests..."

# Monitor canary performance
REQUESTS_SEEN=0
ERRORS=0

while [ $REQUESTS_SEEN -lt $CANARY_REQUESTS ]; do
  # Check canary health
  if ! curl -f http://localhost:8001/health > /dev/null 2>&1; then
    ((ERRORS++))
  fi

  ((REQUESTS_SEEN++))

  # Check error rate
  ERROR_RATE=$((ERRORS * 100 / REQUESTS_SEEN))
  if [ $ERROR_RATE -gt 5 ]; then
    echo "Error rate too high ($ERROR_RATE%). Rolling back canary..."
    sudo rm /etc/nginx/sites-enabled/web3audit-canary
    sudo systemctl reload nginx
    docker stop web3audit-canary
    docker rm web3audit-canary
    exit 1
  fi

  sleep 1
done

echo "Canary deployment successful. Promoting to full production..."

# Full deployment
sudo sed -i 's/weight=9/weight=0/' /etc/nginx/sites-available/web3audit-canary
sudo sed -i 's/weight=1/weight=10/' /etc/nginx/sites-available/web3audit-canary
sudo systemctl reload nginx

# Stop old version
docker stop web3audit-stable
docker rm web3audit-stable

echo "Full deployment completed"
```

---

## Monitoring and Observability

### Application Metrics

#### Prometheus Metrics

```python
from prometheus_client import Counter, Histogram, Gauge, generate_latest
import time

class AuditMetrics:
    """Application metrics for monitoring."""

    def __init__(self):
        # Counters
        self.audits_started = Counter(
            'web3audit_audits_started_total',
            'Total number of audits started'
        )
        self.audits_completed = Counter(
            'web3audit_audits_completed_total',
            'Total number of audits completed',
            ['status']  # success, failed, timeout
        )
        self.findings_discovered = Counter(
            'web3audit_findings_discovered_total',
            'Total number of findings discovered',
            ['severity']  # critical, high, medium, low, info
        )

        # Histograms
        self.audit_duration = Histogram(
            'web3audit_audit_duration_seconds',
            'Time taken to complete audits',
            buckets=[60, 300, 600, 1800, 3600, 7200]
        )
        self.agent_processing_time = Histogram(
            'web3audit_agent_processing_time_seconds',
            'Time taken by agents to process tasks',
            ['agent_type']
        )

        # Gauges
        self.active_audits = Gauge(
            'web3audit_active_audits',
            'Number of currently active audits'
        )
        self.queue_size = Gauge(
            'web3audit_queue_size',
            'Number of audits waiting in queue'
        )
        self.memory_usage = Gauge(
            'web3audit_memory_usage_bytes',
            'Current memory usage'
        )

    def record_audit_start(self):
        """Record audit start."""
        self.audits_started.inc()
        self.active_audits.inc()

    def record_audit_completion(self, status: str, duration: float):
        """Record audit completion."""
        self.audits_completed.labels(status=status).inc()
        self.audit_duration.observe(duration)
        self.active_audits.dec()

    def record_findings(self, findings: List[dict]):
        """Record discovered findings."""
        for finding in findings:
            self.findings_discovered.labels(
                severity=finding.get('severity', 'unknown').lower()
            ).inc()

    def update_queue_size(self, size: int):
        """Update queue size gauge."""
        self.queue_size.set(size)

    def update_memory_usage(self):
        """Update memory usage gauge."""
        import psutil
        process = psutil.Process()
        memory_bytes = process.memory_info().rss
        self.memory_usage.set(memory_bytes)

# Global metrics instance
metrics = AuditMetrics()
```

#### Health Checks

```python
from flask import Flask, jsonify
import psutil
import time

app = Flask(__name__)

class HealthChecker:
    """Comprehensive health checking."""

    def __init__(self):
        self.start_time = time.time()
        self.last_health_check = 0
        self.health_check_interval = 30  # seconds

    def check_database(self) -> dict:
        """Check database connectivity."""
        try:
            # Database connection test
            db_connection_test()
            return {"status": "healthy", "response_time": 0.1}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}

    def check_redis(self) -> dict:
        """Check Redis connectivity."""
        try:
            redis_connection_test()
            return {"status": "healthy", "response_time": 0.05}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}

    def check_tools(self) -> dict:
        """Check analysis tools availability."""
        tools_status = {}

        # Check Slither
        try:
            result = subprocess.run(
                ["slither", "--version"],
                capture_output=True,
                timeout=10
            )
            tools_status["slither"] = {
                "status": "healthy" if result.returncode == 0 else "unhealthy",
                "version": result.stdout.decode().strip()
            }
        except Exception as e:
            tools_status["slither"] = {"status": "unhealthy", "error": str(e)}

        return tools_status

    def check_system_resources(self) -> dict:
        """Check system resource usage."""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        return {
            "cpu_usage": cpu_percent,
            "memory_usage": memory.percent,
            "disk_usage": disk.percent,
            "cpu_status": "healthy" if cpu_percent < 90 else "warning",
            "memory_status": "healthy" if memory.percent < 85 else "warning",
            "disk_status": "healthy" if disk.percent < 90 else "warning"
        }

    def overall_health(self) -> dict:
        """Return overall system health."""
        current_time = time.time()

        # Cache health checks
        if current_time - self.last_health_check < self.health_check_interval:
            return self._cached_health

        # Perform comprehensive health check
        health_data = {
            "timestamp": current_time,
            "uptime": current_time - self.start_time,
            "version": get_version(),
            "database": self.check_database(),
            "redis": self.check_redis(),
            "tools": self.check_tools(),
            "system": self.check_system_resources()
        }

        # Determine overall status
        component_statuses = [
            health_data["database"]["status"],
            health_data["redis"]["status"],
            health_data["system"]["cpu_status"],
            health_data["system"]["memory_status"],
            health_data["system"]["disk_status"]
        ]

        if "unhealthy" in component_statuses:
            overall_status = "unhealthy"
        elif "warning" in component_statuses:
            overall_status = "warning"
        else:
            overall_status = "healthy"

        health_data["status"] = overall_status
        self._cached_health = health_data
        self.last_health_check = current_time

        return health_data

health_checker = HealthChecker()

@app.route('/health')
def health():
    """Health check endpoint."""
    health_data = health_checker.overall_health()
    status_code = 200 if health_data["status"] == "healthy" else 503
    return jsonify(health_data), status_code

@app.route('/health/detailed')
def detailed_health():
    """Detailed health check endpoint."""
    return jsonify(health_checker.overall_health())
```

### Logging Configuration

```python
# logging_config.yaml
version: 1
disable_existing_loggers: false

formatters:
  json:
    class: pythonjsonlogger.jsonlogger.JsonFormatter
    format: "%(asctime)s %(name)s %(levelname)s %(message)s"

  detailed:
    format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s - %(pathname)s:%(lineno)d"

handlers:
  console:
    class: logging.StreamHandler
    level: INFO
    formatter: detailed
    stream: ext://sys.stdout

  file:
    class: logging.handlers.RotatingFileHandler
    level: INFO
    formatter: json
    filename: /var/log/web3audit/application.log
    maxBytes: 10485760  # 10MB
    backupCount: 5

  error_file:
    class: logging.handlers.RotatingFileHandler
    level: ERROR
    formatter: json
    filename: /var/log/web3audit/error.log
    maxBytes: 10485760
    backupCount: 10

  audit_trail:
    class: logging.handlers.RotatingFileHandler
    level: INFO
    formatter: json
    filename: /var/log/web3audit/audit_trail.log
    maxBytes: 10485760
    backupCount: 30

loggers:
  web3_security_ai:
    level: INFO
    handlers: [console, file, error_file]
    propagate: false

  audit_trail:
    level: INFO
    handlers: [audit_trail]
    propagate: false

root:
  level: INFO
  handlers: [console, file, error_file]
```

### Alerting

```python
from web3_security_ai.monitoring import AlertManager

class ProductionAlertManager(AlertManager):
    """Production alerting system."""

    def __init__(self):
        self.alert_channels = {
            "email": EmailAlertChannel(),
            "slack": SlackAlertChannel(),
            "pagerduty": PagerDutyAlertChannel()
        }

    def alert_critical_failure(self, component: str, error: str):
        """Alert on critical system failures."""
        alert = {
            "severity": "critical",
            "component": component,
            "message": f"Critical failure in {component}: {error}",
            "timestamp": datetime.utcnow().isoformat()
        }

        # Send to all channels
        for channel in self.alert_channels.values():
            channel.send_alert(alert)

    def alert_performance_degradation(self, metric: str, value: float, threshold: float):
        """Alert on performance degradation."""
        alert = {
            "severity": "warning",
            "component": "performance",
            "message": f"Performance degradation: {metric} = {value} (threshold: {threshold})",
            "timestamp": datetime.utcnow().isoformat()
        }

        # Send to monitoring channels only
        self.alert_channels["slack"].send_alert(alert)
        self.alert_channels["email"].send_alert(alert)

    def alert_security_incident(self, incident_type: str, details: dict):
        """Alert on security incidents."""
        alert = {
            "severity": "critical",
            "component": "security",
            "message": f"Security incident detected: {incident_type}",
            "details": details,
            "timestamp": datetime.utcnow().isoformat()
        }

        # Send to all channels with high priority
        for channel in self.alert_channels.values():
            channel.send_alert(alert, priority="high")
```

---

## Performance Tuning

### Memory Optimization

```python
import gc
import psutil
from functools import lru_cache

class MemoryOptimizer:
    """Memory optimization strategies."""

    def __init__(self, max_memory_gb: float = 4.0):
        self.max_memory_gb = max_memory_gb
        self.process = psutil.Process()

    def should_gc(self) -> bool:
        """Check if garbage collection should be run."""
        memory_usage = self.get_memory_usage_gb()
        return memory_usage > self.max_memory_gb * 0.8

    def get_memory_usage_gb(self) -> float:
        """Get current memory usage in GB."""
        memory_info = self.process.memory_info()
        return memory_info.rss / (1024 ** 3)

    def optimize_memory(self):
        """Perform memory optimization."""
        # Force garbage collection
        gc.collect()

        # Clear LRU caches if they exist
        if hasattr(self, 'analysis_cache'):
            self.analysis_cache.clear()

        # Clear any temporary data structures
        self._clear_temp_data()

    def _clear_temp_data(self):
        """Clear temporary data structures."""
        # Implementation depends on specific data structures used
        pass

@lru_cache(maxsize=100)
def cached_contract_analysis(contract_hash: str, analysis_type: str) -> dict:
    """Cache contract analysis results."""
    # Implementation
    pass
```

### CPU Optimization

```python
import multiprocessing as mp
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

class CPUOptimizer:
    """CPU optimization strategies."""

    def __init__(self):
        self.cpu_count = mp.cpu_count()

    def get_optimal_thread_pool_size(self, task_type: str) -> int:
        """Get optimal thread pool size for task type."""
        if task_type == 'io_bound':
            return min(32, self.cpu_count * 4)  # More threads for I/O
        elif task_type == 'cpu_bound':
            return max(1, self.cpu_count - 1)  # Fewer threads for CPU
        else:
            return max(1, self.cpu_count * 2)

    def get_optimal_process_pool_size(self, task_type: str) -> int:
        """Get optimal process pool size."""
        if task_type == 'memory_intensive':
            return max(1, self.cpu_count // 2)  # Fewer processes for memory
        else:
            return self.cpu_count

    def create_optimal_executor(self, task_type: str):
        """Create optimally configured executor."""
        if task_type in ['io_bound', 'network']:
            pool_size = self.get_optimal_thread_pool_size(task_type)
            return ThreadPoolExecutor(max_workers=pool_size)
        else:
            pool_size = self.get_optimal_process_pool_size(task_type)
            return ProcessPoolExecutor(max_workers=pool_size)
```

### Database Optimization

```sql
-- Optimized database indexes
CREATE INDEX CONCURRENTLY idx_audit_sessions_status_created
ON audit_sessions (status, created_at DESC);

CREATE INDEX CONCURRENTLY idx_audit_findings_audit_id_severity
ON audit_findings (audit_id, severity);

CREATE INDEX CONCURRENTLY idx_audit_findings_type
ON audit_findings USING gin (type gin_trgm_ops);

-- Partitioning for large tables
CREATE TABLE audit_sessions_y2024m01 PARTITION OF audit_sessions
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

-- Database configuration optimizations
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET work_mem = '4MB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
```

### Caching Strategies

```python
from cachetools import TTLCache, LRUCache
import redis

class CacheManager:
    """Multi-level caching system."""

    def __init__(self, redis_client=None):
        # L1: In-memory LRU cache
        self.l1_cache = LRUCache(maxsize=1000)

        # L2: TTL cache for temporary data
        self.l2_cache = TTLCache(maxsize=5000, ttl=3600)

        # L3: Redis for distributed caching
        self.redis = redis_client

    def get(self, key: str):
        """Get value from cache hierarchy."""
        # Check L1 cache
        value = self.l1_cache.get(key)
        if value is not None:
            return value

        # Check L2 cache
        value = self.l2_cache.get(key)
        if value is not None:
            # Promote to L1
            self.l1_cache[key] = value
            return value

        # Check Redis
        if self.redis:
            value = self.redis.get(key)
            if value is not None:
                # Promote to higher caches
                self.l2_cache[key] = value
                self.l1_cache[key] = value
                return value

        return None

    def set(self, key: str, value, ttl: int = None):
        """Set value in cache hierarchy."""
        # Set in L1
        self.l1_cache[key] = value

        # Set in L2 with TTL
        self.l2_cache[key] = value

        # Set in Redis with TTL
        if self.redis:
            self.redis.setex(key, ttl or 3600, value)

    def invalidate_pattern(self, pattern: str):
        """Invalidate cache entries matching pattern."""
        # Invalidate L1 and L2 (simplified)
        keys_to_remove = [k for k in self.l1_cache.keys() if pattern in k]
        for key in keys_to_remove:
            self.l1_cache.pop(key, None)
            self.l2_cache.pop(key, None)

        # Invalidate Redis
        if self.redis:
            keys = self.redis.keys(pattern)
            if keys:
                self.redis.delete(*keys)
```

---

## Backup and Recovery

### Database Backup

```bash
#!/bin/bash
# Database backup script

BACKUP_DIR="/opt/web3audit/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="web3audit_backup_$DATE"

# Create backup directory
mkdir -p $BACKUP_DIR

# Database backup
pg_dump -h localhost -U web3audit -d web3audit -Fc > $BACKUP_DIR/${BACKUP_NAME}.dump

# Compress backup
gzip $BACKUP_DIR/${BACKUP_NAME}.dump

# Upload to cloud storage
aws s3 cp $BACKUP_DIR/${BACKUP_NAME}.dump.gz s3://web3audit-backups/database/

# Clean old backups (keep last 30 days)
find $BACKUP_DIR -name "*.dump.gz" -mtime +30 -delete

# Log backup completion
echo "$(date): Database backup completed - $BACKUP_NAME" >> /var/log/web3audit/backup.log
```

### Configuration Backup

```bash
#!/bin/bash
# Configuration backup script

BACKUP_DIR="/opt/web3audit/backups/config"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup configurations
tar -czf $BACKUP_DIR/config_backup_$DATE.tar.gz \
    /opt/web3audit/.env \
    /opt/web3audit/app/config/ \
    /etc/systemd/system/web3audit.service \
    /etc/nginx/sites-available/web3audit

# Upload to cloud storage
aws s3 cp $BACKUP_DIR/config_backup_$DATE.tar.gz s3://web3audit-backups/config/

# Clean old backups (keep last 90 days)
find $BACKUP_DIR -name "*.tar.gz" -mtime +90 -delete
```

### File System Backup

```bash
#!/bin/bash
# File system backup script

BACKUP_DIR="/opt/web3audit/backups/filesystem"
SOURCE_DIR="/opt/web3audit"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup application data (excluding logs and temp files)
rsync -av --exclude='logs/' --exclude='temp/' --exclude='.git/' \
    $SOURCE_DIR/ $BACKUP_DIR/backup_$DATE/

# Compress backup
tar -czf $BACKUP_DIR/backup_$DATE.tar.gz -C $BACKUP_DIR backup_$DATE

# Upload to cloud storage
aws s3 cp $BACKUP_DIR/backup_$DATE.tar.gz s3://web3audit-backups/filesystem/

# Clean up local backup
rm -rf $BACKUP_DIR/backup_$DATE

# Clean old backups (keep last 30 days)
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete
```

### Recovery Procedures

#### Database Recovery

```bash
#!/bin/bash
# Database recovery script

BACKUP_FILE=$1
DB_NAME="web3audit"
DB_USER="web3audit"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

# Stop application
sudo systemctl stop web3audit

# Drop and recreate database
sudo -u postgres dropdb $DB_NAME
sudo -u postgres createdb $DB_NAME
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"

# Restore from backup
pg_restore -h localhost -U $DB_USER -d $DB_NAME $BACKUP_FILE

# Run migrations if needed
sudo -u web3audit bash -c "cd /opt/web3audit/app && source ../venv/bin/activate && python manage.py migrate"

# Start application
sudo systemctl start web3audit

echo "Database recovery completed"
```

#### Application Recovery

```bash
#!/bin/bash
# Application recovery script

BACKUP_FILE=$1
APP_DIR="/opt/web3audit"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

# Stop application
sudo systemctl stop web3audit

# Backup current state
mv $APP_DIR ${APP_DIR}.old.$(date +%s)

# Extract backup
mkdir -p $APP_DIR
tar -xzf $BACKUP_FILE -C $APP_DIR

# Restore configurations
cp ${APP_DIR}.old*/.env $APP_DIR/ 2>/dev/null || true

# Restore virtual environment
python3.12 -m venv $APP_DIR/venv
source $APP_DIR/venv/bin/activate
pip install -r $APP_DIR/app/requirements.txt

# Start application
sudo systemctl start web3audit

# Clean up old backup
rm -rf ${APP_DIR}.old.*

echo "Application recovery completed"
```

### Disaster Recovery Plan

#### Recovery Time Objectives (RTO)
- **Critical Systems**: 1 hour
- **Database**: 4 hours
- **Application**: 2 hours
- **Full System**: 8 hours

#### Recovery Point Objectives (RPO)
- **Database**: 1 hour (transaction logs)
- **Configurations**: 1 day
- **File System**: 1 day

#### DR Testing Schedule
- **Monthly**: Component-level recovery testing
- **Quarterly**: Full system failover testing
- **Annually**: Complete disaster recovery simulation

---

## Security Hardening

### System Hardening

```bash
#!/bin/bash
# System hardening script

# Update system
apt update && apt upgrade -y

# Install security packages
apt install -y ufw fail2ban auditd apparmor

# Configure firewall
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80
ufw allow 443
ufw --force enable

# Configure fail2ban
cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

systemctl enable fail2ban
systemctl start fail2ban

# Configure auditd
cat > /etc/audit/rules.d/web3audit.rules << EOF
# Audit file access
-a always,exit -F arch=b64 -S open,openat,execve -F path=/opt/web3audit
-a always,exit -F arch=b32 -S open,openat,execve -F path=/opt/web3audit

# Audit network activity
-a always,exit -F arch=b64 -S socket,bind,connect -F key=network
-a always,exit -F arch=b32 -S socket,bind,connect -F key=network
EOF

systemctl enable auditd
systemctl start auditd

# Secure SSH
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl reload sshd

echo "System hardening completed"
```

### Application Security

```python
from flask import Flask, request, g
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import functools

app = Flask(__name__)

class SecurityManager:
    """Application security manager."""

    def __init__(self, secret_key: str):
        self.secret_key = secret_key

    def generate_token(self, user_id: str, role: str) -> str:
        """Generate JWT token with role-based claims."""
        payload = {
            'user_id': user_id,
            'role': role,
            'exp': datetime.utcnow() + timedelta(hours=24),
            'iat': datetime.utcnow(),
            'iss': 'web3-security-audit'
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')

    def verify_token(self, token: str) -> dict:
        """Verify and decode JWT token."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError:
            raise AuthenticationError("Invalid token")

    def require_role(self, required_role: str):
        """Decorator for role-based access control."""
        def decorator(f):
            @functools.wraps(f)
            def decorated_function(*args, **kwargs):
                auth_header = request.headers.get('Authorization')
                if not auth_header or not auth_header.startswith('Bearer '):
                    return {'error': 'Missing or invalid authorization header'}, 401

                token = auth_header.split(' ')[1]
                try:
                    payload = self.verify_token(token)
                    user_role = payload.get('role')

                    if user_role not in self._get_role_hierarchy(required_role):
                        return {'error': 'Insufficient permissions'}, 403

                    g.user_id = payload.get('user_id')
                    g.user_role = user_role

                except AuthenticationError as e:
                    return {'error': str(e)}, 401

                return f(*args, **kwargs)
            return decorated_function
        return decorator

    def _get_role_hierarchy(self, role: str) -> list:
        """Get role hierarchy for permission checking."""
        hierarchies = {
            'admin': ['admin', 'auditor', 'viewer'],
            'auditor': ['auditor', 'viewer'],
            'viewer': ['viewer']
        }
        return hierarchies.get(role, [role])

# Rate limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Input validation
from cerberus import Validator

audit_request_schema = {
    'target': {'required': True, 'type': 'string', 'maxlength': 1000},
    'target_type': {'required': True, 'allowed': ['contract', 'protocol', 'dapp']},
    'analysis_config': {
        'type': 'dict',
        'schema': {
            'depth': {'allowed': ['basic', 'standard', 'comprehensive', 'deep']},
            'tools': {'type': 'list', 'schema': {'type': 'string'}},
            'timeout': {'type': 'integer', 'min': 1, 'max': 3600}
        }
    }
}

def validate_audit_request(data: dict) -> dict:
    """Validate audit request data."""
    validator = Validator(audit_request_schema)
    if not validator.validate(data):
        raise ValidationError(f"Invalid request data: {validator.errors}")
    return validator.document

# Security headers
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# Initialize security manager
security_manager = SecurityManager(app.config['SECRET_KEY'])

@app.route('/api/v1/audit/submit', methods=['POST'])
@limiter.limit("10 per hour")
@security_manager.require_role('auditor')
def submit_audit():
    """Submit audit request with security controls."""
