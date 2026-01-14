# 🔍 Ghidra BSim PostgreSQL Database Platform

[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)
[![Ghidra](https://img.shields.io/badge/Ghidra_BSim-PostgreSQL-orange.svg)](https://ghidra-sre.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue.svg)](https://postgresql.org)
[![Security](https://img.shields.io/badge/Security-Production_Ready-green.svg)](PRODUCTION-SECURITY.md)
[![Version](https://img.shields.io/badge/Version-v1.0.0-blue.svg)](VERSION)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A comprehensive Docker-based platform for **Ghidra BSim (Binary Similarity)** analysis with PostgreSQL backend. This setup enables large-scale binary similarity analysis, malware family classification, and code reuse detection using Ghidra's official BSim tools with a production-ready PostgreSQL database.

## ✨ Key Features

### 🚀 BSim Database Platform
- **Auto-Initialization** - BSim schema automatically created on first startup (NEW!)
- **Large-Scale Analysis** - Supports ~100 million functions with large_32 template
- **PostgreSQL Backend** - Production-ready database with SSL support
- **Official LSH Extension** - Built from Ghidra source for optimal performance
- **Schema Compatibility** - Official Ghidra BSim tables (exetable, desctable, vectable) with full compatibility
- **One-Command Setup** - Start and go - no manual schema setup required
- **Comprehensive Testing** - Automated validation of all components

### 🛠️ Management & Operations
- **Automated Backups** - Scheduled weekly backups with retention policies
- **Real-time Monitoring** - Database performance and capacity monitoring
- **Health Alerts** - Proactive monitoring with configurable thresholds
- **SSL Security** - Full SSL/TLS encryption with certificate management
- **Cross-Platform** - Ubuntu Linux optimized, Windows/macOS compatible
- **Flexible Deployment** - Auto or manual schema creation modes

### 🔬 Analysis Capabilities
- **Binary Similarity** - Find similar functions across different executables
- **Malware Analysis** - Classify and cluster malware families
- **Code Reuse Detection** - Identify shared code libraries and components
- **Large Dataset Support** - Optimized for enterprise-scale analysis
- **Ghidra Integration** - Seamless integration with Ghidra BSim tools

---

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Ghidra 11.4.2 or newer (for analysis only - not required for database setup)
- 8GB+ RAM recommended

### 1. Start BSim Database (Auto-Initialization)
```bash
git clone <repository-url>
cd re-universe

# Configure environment (first time only)
cp .env.example .env
# Edit .env and set BSIM_DB_PASSWORD

# Start the database (BSim schema auto-created!)
./start-bsim.sh

# Wait ~30 seconds for initialization
docker logs bsim-postgres -f

# Verify BSim schema is ready
docker exec -it bsim-postgres psql -U ben -d bsim -c "\dt"
```

**Expected output:**
```
            List of relations
 Schema |       Name       | Type  | Owner 
--------+------------------+-------+-------
 public | archtable        | table | ben
 public | callgraph        | table | ben
 public | callgraphtable   | table | ben
 public | cattable         | table | ben
 public | desctable        | table | ben
 public | exetable         | table | ben
 ...
(18 rows)
```

### 2. Connect from Ghidra
1. Open Ghidra → **Tools** → **BSim Search**
2. Server: `postgresql://ben:[password]@localhost:5432/bsim`
3. Enable **"Use SSL"**
4. Test connection - **Schema already created, ready to use!**

### 3. Ingest Your First Binary
```bash
# Using Ghidra BSim tools
cd /path/to/ghidra
./support/bsim generatesigs postgresql://ben:[password]@localhost:5432/bsim /path/to/your/binary.exe

# Query for similar functions
./support/bsim query postgresql://ben:[password]@localhost:5432/bsim --function "FUN_00401000"
```

---

## 📋 Installation & Setup

### Automatic Setup (Recommended - NEW!)

**Default behavior**: BSim schema is **automatically created** on first container startup.

```bash
# Clone the repository
git clone <repository-url>
cd re-universe

# Configure environment
cp .env.example .env
# Edit .env: Set BSIM_DB_PASSWORD and optionally AUTO_CREATE_BSIM_SCHEMA=true

# Start BSim database (auto-creates schema)
./start-bsim.sh

# Wait for initialization (~30 seconds)
docker logs bsim-postgres -f

# Test the setup (validates BSim schema exists)
./test-bsim-setup.sh

# Monitor database status
./monitor-bsim.sh
```

**Result**: Database ready with:
- ✅ 18 BSim tables (exetable, desctable, vectable, etc.)
- ✅ Helper functions (insert_vec, remove_vec)
- ✅ LSH extension enabled
- ✅ SSL certificates configured
- ✅ Ready for Ghidra BSim tools

### Manual Setup (For Custom Configurations)

If you prefer manual schema creation or need a custom template:

```bash
# In .env file
AUTO_CREATE_BSIM_SCHEMA=false

# Start container (minimal initialization only)
./start-bsim.sh

# Option 1: Use Ghidra CLI to create schema
cd /path/to/ghidra
./support/bsim createdatabase postgresql://ben:[password]@localhost:5432/bsim medium_32
# Templates: medium_32, large_32, medium_64, large_64

# Option 2: Manual SQL execution
docker exec -i bsim-postgres psql -U ben -d bsim < bsim-init/04-create-bsim-schema.sql
```

#### LSH Extension (Included in Docker Image)

**No manual build required!** The LSH extension is pre-built into the Docker image.

If you need to rebuild the image:

```bash
# LSH extension source in: bsim-postgres/Dockerfile
# Build command:
docker-compose build bsim-postgres
```

---

## ⚙️ Configuration

### Environment Variables
Edit `.env` to customize your setup:

```bash
# BSim Database Configuration
BSIM_DB_NAME=bsim
BSIM_DB_USER=ben                       # Default user (change as needed)
BSIM_DB_PASSWORD=your_secure_password  # REQUIRED: Set a secure password
BSIM_DB_PORT=5432

# Auto-Initialization (NEW!)
AUTO_CREATE_BSIM_SCHEMA=true           # Auto-create BSim schema on first startup
                                       # Options: true (auto), false (manual)
                                       # Default: true (recommended)

# Backup Configuration
BACKUP_RETENTION_WEEKS=4
BACKUP_SCHEDULE="0 2 * * 0"            # Weekly on Sunday at 2 AM
```

### Schema Template

The auto-creation uses **large_32** template (100M functions, 32-bit executables).

To use a different template:
1. Set `AUTO_CREATE_BSIM_SCHEMA=false` in `.env`
2. Manually create schema with desired template:
   ```bash
   ./support/bsim createdatabase postgresql://ben:pass@localhost:5432/bsim medium_32
   ```

### Database Templates

| Template | Description | Architecture | Capacity | Auto-Created |
|----------|-------------|--------------|----------|--------------|
| `large_32` | Large database | 32-bit | ~100M functions | ✅ Default |
| `large_64` | Large database | 64-bit | ~100M functions | ❌ Manual |
| `medium_32` | Medium database | 32-bit | ~10M functions | ❌ Manual |
| `medium_64` | Medium database | 64-bit | ~10M functions |
| `medium_nosize` | Size-agnostic | Mixed | ~10M functions |

**Recommended**: `large_32` for production use with mixed 32/64-bit binaries.

---

## 💻 Usage

### Platform Management

#### Start/Stop Database
```bash
# Start BSim database
./start-bsim.sh

# Stop BSim database
./stop-bsim.sh

# Restart with clean volumes (DATA LOSS!)
./stop-bsim.sh --remove --volumes
./start-bsim.sh
```

#### Database Monitoring
```bash
# Basic status
./monitor-bsim.sh

# Detailed metrics
./monitor-bsim.sh metrics

# Performance monitoring
./monitor-bsim.sh performance

# Continuous monitoring
./monitor-bsim.sh watch performance

# Check for alerts
./monitor-bsim.sh alerts
```

### Binary Analysis Workflows

#### 1. Single Binary Analysis
```bash
# Ingest binary into BSim database
./ingest-binary.sh /path/to/malware.exe

# Query similar functions in Ghidra
# Tools → BSim Search → Query Functions
# Set similarity threshold (0.7+ recommended)
```

#### 2. Batch Analysis
```bash
# Ingest multiple binaries
find /malware/samples -name "*.exe" -exec ./ingest-binary.sh {} \;

# Parallel ingestion for large datasets
./parallel-ingest.sh --directory /large/dataset --threads 8
```

#### 3. Similarity Search
```bash
# Command-line similarity query
./query-bsim.sh --function "main" --threshold 0.8 --output results.json

# Batch similarity analysis
./batch-similarity.sh --input-list binaries.txt --output similarity-report.json
```

### Database Administration

#### Backup Management
```bash
# Create manual backup
./bsim-backup.sh --name "pre-analysis-backup"

# List available backups
ls -la backups/bsim/

# Restore from backup
./restore-bsim.sh --backup "pre-analysis-backup"

# Automated backup status
crontab -l | grep bsim
```

#### Performance Optimization
```bash
# Update database statistics
./maintain-bsim.sh --update-stats

# Reindex for better performance
./maintain-bsim.sh --reindex

# Clean up orphaned data
./maintain-bsim.sh --cleanup
```

---

## 🧪 Testing & Validation

### Automated Testing
```bash
# Run all tests
./test-bsim-setup.sh

# Run comprehensive tests (includes performance)
./test-bsim-setup.sh --comprehensive

# Test specific components
./test-bsim-setup.sh --test ssl
./test-bsim-setup.sh --test lsh
./test-bsim-setup.sh --test schema

# Verbose testing
./test-bsim-setup.sh --verbose
```

### Manual Validation
```bash
# Test database connection
docker exec bsim-postgres psql -U ben -d bsim -c "SELECT version();"

# Verify BSim schema
docker exec bsim-postgres psql -U ben -d bsim -c "SELECT * FROM bsim_database_info();"

# Check LSH extension
docker exec bsim-postgres psql -U ben -d bsim -c "\dx lsh"

# Test LSH functions
docker exec bsim-postgres psql -U ben -d bsim -c "SELECT lsh_compare('{1,2,3}', '{1,2,4}');"
```

---

## 🔧 Troubleshooting

### Common Issues

#### 1. "Database does not exist"
```bash
# Check container status
docker ps | grep bsim-postgres

# Restart container if needed
docker-compose restart bsim-postgres

# Reinitialize if corrupted
docker-compose down
docker volume rm re-universe_bsim_postgres_data
docker-compose up -d bsim-postgres
```

#### 2. "LSH functions not found"
```bash
# Check if LSH extension is installed
docker exec bsim-postgres psql -U ben -d bsim -c "\dx lsh"

# Rebuild LSH extension if needed
cd ghidra/Ghidra/Features/BSim/src/lshvector
make clean && make && sudo make install
```

#### 3. "The server does not support SSL" (BSim Creation Error)
```bash
# This error occurs when Ghidra BSim tries to connect to PostgreSQL without SSL
# ERROR: Cannot create PoolableConnectionFactory (The server does not support SSL.)

# Check SSL status
docker exec bsim-postgres psql -U ben -d bsim -c "SHOW ssl;"

# If SSL is off, enable it in docker-compose.yml:
# Add "-c ssl=on" to postgres command and restart:
docker-compose restart bsim-postgres

# Verify SSL is working
docker exec bsim-postgres psql -U ben -d bsim -c "SELECT 'SSL enabled' as status;"

# See BSIM-SSL-SETUP.md for detailed SSL configuration guide
```

#### 4. Performance Issues
```bash
# Check database size and usage
./monitor-bsim.sh metrics

# Monitor resource usage
docker stats bsim-postgres

# Consider upgrading template for large datasets
./migrate-bsim.sh --from large_32 --to large_64
```

### Debug Commands
```bash
# Container logs
docker logs bsim-postgres

# PostgreSQL logs
docker exec bsim-postgres tail -f /var/log/postgresql/postgresql-15-main.log

# Database diagnostics
./monitor-bsim.sh alerts

# Connection testing
nc -z localhost 5432
telnet localhost 5432
```

---

## 📚 Advanced Usage

### Custom Templates
```bash
# Create custom BSim template
./create-bsim-template.sh \
    --name "malware_analysis" \
    --k 15 \
    --L 128 \
    --description "Optimized for malware analysis"

# Use custom template
./setup-bsim.sh --template "malware_analysis"
```

### Integration Examples

#### CI/CD Pipeline Integration
```yaml
# .github/workflows/malware-analysis.yml
name: Automated Malware Analysis

on:
  push:
    paths: ['samples/**']

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Start BSim Database
        run: ./start-bsim.sh
      - name: Analyze New Samples
        run: ./ci-bsim-analysis.sh --new-samples samples/ --report reports/
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: analysis-results
          path: reports/
```

#### Python API Integration
```python
import psycopg2
import json

# Connect to BSim database
conn = psycopg2.connect(
    host="localhost",
    port=5432,
    database="bsim",
    user="your_username",
    password="your_password",
    sslmode="require"
)

# Query similar functions
cursor = conn.cursor()
cursor.execute("""
    SELECT e.name_exec, f.name_func, s.significance
    FROM executable e
    JOIN function f ON e.id = f.executable_id
    JOIN signature s ON f.id = s.function_id
    WHERE s.significance > 0.8
    ORDER BY s.significance DESC
    LIMIT 100
""")

results = cursor.fetchall()
print(json.dumps(results, indent=2))
```

---

## 📄 Documentation

### Setup & Configuration
- **[BSIM-SETUP.md](BSIM-SETUP.md)** - Comprehensive setup and configuration guide
- **[PRODUCTION-SECURITY.md](PRODUCTION-SECURITY.md)** - **Critical security requirements for production**
- **[PRODUCTION-DEPLOYMENT.md](PRODUCTION-DEPLOYMENT.md)** - **Step-by-step production deployment guide**

### Operations & Troubleshooting
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Detailed troubleshooting procedures
- **[API.md](API.md)** - Database schema and API reference

### 🚨 **Security Notice**
> **⚠️ IMPORTANT**: This platform contains default credentials for development only.
> **Read [PRODUCTION-SECURITY.md](PRODUCTION-SECURITY.md) before production deployment.**

### Script Reference
- **[start-bsim.sh](start-bsim.sh)** - Start BSim database (`--help` for options)
- **[stop-bsim.sh](stop-bsim.sh)** - Stop BSim database
- **[test-bsim-setup.sh](test-bsim-setup.sh)** - Comprehensive testing
- **[monitor-bsim.sh](monitor-bsim.sh)** - Database monitoring and alerts
- **[bsim-backup.sh](bsim-backup.sh)** - Backup management

### Configuration Files
- **[docker-compose.yml](docker-compose.yml)** - Container orchestration
- **[create-bsim-schema.sql](create-bsim-schema.sql)** - Database schema definition
- **[.env.example](.env.example)** - Configuration template

---

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/re-universe.git`
3. Test the setup: `./test-bsim-setup.sh --comprehensive`
4. Make your changes
5. Test on multiple platforms (Ubuntu, Windows, macOS)
6. Submit a pull request

### Testing Checklist
- [ ] BSim database starts correctly
- [ ] LSH extension functions properly
- [ ] SSL connections work
- [ ] Backup/restore cycle works
- [ ] Monitoring scripts function
- [ ] Documentation is updated

---

## 📞 Support

### Getting Help
1. **Read the documentation** - [BSIM-SETUP.md](BSIM-SETUP.md) has detailed instructions
2. **Run diagnostics** - `./test-bsim-setup.sh --verbose`
3. **Check logs** - `./monitor-bsim.sh logs`
4. **Search GitHub Issues** - Check existing issues and discussions
5. **Create new issue** - Provide full error output and system information

### Quick Diagnostics
```bash
# Complete system status
./monitor-bsim.sh alerts

# Database connectivity test
./test-bsim-setup.sh --test database

# Performance check
./monitor-bsim.sh performance

# Log analysis
./monitor-bsim.sh logs
```

---

## 🙏 Acknowledgments

- **[Ghidra Team](https://github.com/NationalSecurityAgency/ghidra)** - For the excellent BSim framework
- **[PostgreSQL](https://postgresql.org)** - For robust database backend
- **[Docker](https://docker.com)** - For containerization platform
- **Security Research Community** - For feedback and contributions

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

*Built with ❤️ for the binary analysis and reverse engineering community*

> **Security Note**: This platform is designed for defensive security research and malware analysis. Ensure compliance with your organization's security policies and legal requirements when analyzing potentially malicious code.