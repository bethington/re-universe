# 🔍 Reverse Engineering Analysis Platform

[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)
[![Cross Platform](https://img.shields.io/badge/Cross_Platform-Windows%20%7C%20Linux%20%7C%20macOS-green.svg)](https://github.com/topics/cross-platform)
[![Ghidra](https://img.shields.io/badge/Ghidra-Server-orange.svg)](https://ghidra-sre.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A comprehensive Docker-based reverse engineering platform that integrates **Ghidra Server**, **ret-sync**, and **x64dbg** for collaborative static and dynamic analysis. Supports cross-platform development with PowerShell (Windows) and Bash (Linux/macOS) scripts.

## ✨ Features

### 🚀 Core Functionality

- **Ghidra Server Backend** - Collaborative reverse engineering with shared repositories
- **Cross-Platform Support** - Windows, Linux, and macOS compatibility
- **Automated Backup System** - Scheduled backups with retention policies
- **Safety-First Operations** - Confirmation prompts and dry-run modes
- **Comprehensive Testing** - Automated connectivity and health checks

### 🛠️ Management Tools

- **Backup & Restore** - Full and incremental backups with metadata
- **Data Cleanup** - Safe cleanup while preserving .gitkeep files
- **Configuration Management** - Environment-based configuration
- **Connectivity Testing** - Multi-method port and service validation
- **Automated Scheduling** - Cron-based backup scheduling

### 🔧 Technical Features

- **Docker Integration** - Containerized infrastructure
- **Environment Variables** - Flexible configuration management
- **Error Handling** - Comprehensive error handling and logging
- **Tool Detection** - Graceful handling of missing dependencies
- **Colored Output** - Enhanced user experience with colored terminal output

---

---

## 🚀 Quick Start

### Windows (PowerShell)

```powershell
# Clone and navigate to project
git clone <repository-url>
cd re-universe

# Start the platform
.\start.ps1

# Test connectivity
.\test-connectivity.ps1

# Create a backup
.\backup.ps1 -BackupName "initial-backup"
```

### Linux/macOS (Bash)

```bash
# Clone and navigate to project
git clone <repository-url>
cd re-universe

# Make scripts executable
chmod +x *.sh

# Start the platform
./start.sh

# Test connectivity
./test-connectivity.sh

# Create a backup
./backup.sh -BackupName "initial-backup"
```

### Docker Only

```bash
# Quick start with Docker Compose
docker-compose up -d

# Check status
docker-compose ps
```

---

---

## 📋 Prerequisites

### Required Software
- **Docker Desktop** (or Docker Engine on Linux)
- **Git** for cloning the repository
- **PowerShell 5.1+** (Windows) or **Bash** (Linux/macOS)

### Optional Software
- **Ghidra** - For client connections to the server
- **x64dbg** - For dynamic analysis integration
- **ret-sync** - For Ghidra ↔ debugger synchronization

### System Requirements
- **RAM**: Minimum 4GB, Recommended 8GB+
- **Disk Space**: 2GB+ for Docker images and analysis data
- **Network**: Internet connection for Docker image downloads

---

## 📦 Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd re-universe
```

### 2. Environment Setup
```bash
# Copy environment template
cp .env.example .env

# Edit configuration (optional)
nano .env  # Linux/macOS
# or
notepad .env  # Windows
```

### 3. Make Scripts Executable (Linux/macOS)
```bash
chmod +x *.sh
```

### 4. First-Time Setup
```powershell
# Windows
.\setup.ps1

# Linux/macOS
./setup.sh
```

---

## ⚙️ Configuration

### Environment Variables

Create a `.env` file with the following variables:

```bash
# Core Configuration
GHIDRA_USERS=admin
GHIDRA_PORT=13100
GHIDRA_IP=localhost

# Backup Configuration
BACKUP_FREQUENCY=hourly
BACKUP_PATH=./backups
RETENTION_DAYS=30

# Advanced Settings
BACKUP_HOUR=02
BACKUP_MINUTE=00
LOG_LEVEL=INFO
```

### Configuration Files

- **`.env`** - Runtime configuration
- **`docker-compose.yml`** - Container orchestration
- **`repo-data/`** - Ghidra repository data
- **`backups/`** - Backup storage location

---

## 💻 Usage

### Platform Management

#### Start the Platform
```powershell
# Windows
.\start.ps1

# Linux/macOS
./start.sh
```

#### Stop the Platform
```powershell
# Windows
.\stop.ps1

# Linux/macOS
./stop.sh
```

#### Check Status
```bash
# Docker containers
docker-compose ps

# Detailed status
docker stats
```

### Connectivity Testing

#### Automated Testing
```powershell
# Windows
.\test-connectivity.ps1

# Linux/macOS
./test-connectivity.sh
```

#### Manual Testing
```bash
# Test port connectivity
nc -z localhost 13100

# Check Docker logs
docker logs ghidra-server
```

### Ghidra Client Connection

1. **Open Ghidra Client**
2. **File → New Project → Shared Project**
3. **Server**: `localhost:13100`
4. **Username**: `admin` (or configured user)
5. **Password**: `changeme`
6. **Create project**: `my-analysis-project`

---

## 💾 Backup & Restore

### Creating Backups

#### Manual Backup
```powershell
# Windows - Simple backup
.\backup.ps1

# Windows - Named backup
.\backup.ps1 -BackupName "weekly-backup"

# Linux/macOS - Simple backup
./backup.sh

# Linux/macOS - Named backup
./backup.sh -BackupName "weekly-backup"
```

#### Scheduled Backups
```powershell
# Windows - Check schedule
.\backup-scheduler.ps1

# Windows - Force backup
.\backup-scheduler.ps1 --force

# Linux/macOS - Check schedule
./backup-scheduler.sh

# Linux/macOS - Force backup
./backup-scheduler.sh --force
```

### Restoring from Backups

#### Interactive Restore
```powershell
# Windows
.\restore.ps1 -BackupFile ".\backups\backup-name.zip"

# Linux/macOS
./restore.sh -BackupFile "./backups/backup-name.zip"
```

#### Force Restore (Skip Confirmation)
```powershell
# Windows
.\restore.ps1 -BackupFile ".\backups\backup-name.zip" -Force

# Linux/macOS
./restore.sh -BackupFile "./backups/backup-name.zip" --force
```

### Backup Management

#### List Available Backups
```powershell
# Windows
Get-ChildItem .\backups\*.zip

# Linux/macOS
ls -la ./backups/*.zip
```

#### Backup Information
```powershell
# Windows
.\backup.ps1 -BackupName "test" -BackupPath ".\backups"

# Linux/macOS
./backup.sh -BackupName "test" -BackupPath "./backups"
```

---

## 🧹 Maintenance

### Data Cleanup

#### Preview Cleanup
```powershell
# Windows - Dry run
.\cleanup.ps1 -DryRun

# Linux/macOS - Dry run
./cleanup.sh --dry-run
```

#### Execute Cleanup
```powershell
# Windows - With confirmation
.\cleanup.ps1

# Windows - Force cleanup
.\cleanup.ps1 -Force

# Linux/macOS - With confirmation
./cleanup.sh

# Linux/macOS - Force cleanup
./cleanup.sh --force
```

#### Selective Cleanup
```powershell
# Skip specific folders
.\cleanup.ps1 -SkipFolders "backups","sync-logs"
./cleanup.sh --skip-folders backups,sync-logs
```

### Log Management

#### View Logs
```bash
# Docker container logs
docker logs ghidra-server

# Follow logs in real-time
docker logs -f ghidra-server

# Backup scheduler logs
cat backup-scheduler.log
```

#### Log Rotation
```bash
# Manual log cleanup
find ./sync-logs -name "*.log" -mtime +30 -delete
```

---

## 🔧 Troubleshooting

### Common Issues

#### Port Already in Use
```powershell
# Windows - Check port usage
netstat -an | findstr :13100

# Linux/macOS - Check port usage
netstat -tlnp | grep :13100

# Kill process using port (replace PID)
taskkill /PID <PID> /F  # Windows
kill -9 <PID>           # Linux/macOS
```

#### Container Won't Start
```bash
# Check container status
docker ps -a

# View detailed logs
docker logs ghidra-server

# Restart containers
docker-compose restart
```

#### Connection Refused
```bash
# Test basic connectivity
ping localhost

# Test port specifically
telnet localhost 13100

# Check firewall settings
# Windows: Windows Defender Firewall
# Linux: sudo ufw status
# macOS: System Preferences > Security & Privacy > Firewall
```

#### Permission Issues
```bash
# Fix script permissions (Linux/macOS)
chmod +x *.sh

# Check file ownership
ls -la repo-data/

# Fix ownership if needed
sudo chown -R $USER:$USER repo-data/
```

### Docker Issues

#### Docker Not Running
```bash
# Start Docker service
# Windows: Start Docker Desktop
# Linux: sudo systemctl start docker
# macOS: Start Docker Desktop

# Verify Docker is running
docker version
```

#### Image Pull Issues
```bash
# Manual image pull
docker pull blacktop/ghidra:latest

# Check disk space
df -h

# Clear Docker cache
docker system prune -a
```

### Performance Issues

#### High Memory Usage
```bash
# Check container resource usage
docker stats

# Limit container memory
# Edit docker-compose.yml and add memory limits
```

#### Slow Analysis
```bash
# Check system resources
top  # Linux/macOS
# Task Manager > Performance  # Windows

# Optimize Ghidra settings
# Edit ghidra.properties for performance tuning
```

---

## 🛠️ Development

### VS Code Integration

This project includes comprehensive VS Code configurations:

#### Launch Configurations
- **🚀 Start Ghidra Server** - Launch the complete platform
- **🛑 Stop Ghidra Server** - Shutdown all containers
- **🔧 Setup Environment** - First-time setup
- **💾 Create Backup** - Manual backup creation
- **🔄 Restore Backup** - Interactive backup restoration
- **🔍 Test Connectivity** - Comprehensive testing

#### Recommended Extensions
```json
{
    "recommendations": [
        "ms-vscode.powershell",
        "ms-azuretools.vscode-docker",
        "redhat.vscode-yaml",
        "ms-vscode.hexeditor",
        "ms-python.python"
    ]
}
```

### Project Structure

```
re-universe/
├── .github/
│   └── copilot-instructions.md
├── backups/                    # Backup storage
├── repo-data/                  # Ghidra repository data
│   ├── server.log             # Server logs
│   ├── users                  # User database
│   ├── ~admin/               # Admin user data
│   └── ~ssh/                 # SSH configuration
├── sync-logs/                 # ret-sync logs
├── docker-compose.yml         # Container orchestration
├── .env                       # Environment configuration
├── .env.example              # Configuration template
├── *.ps1                     # PowerShell scripts (Windows)
├── *.sh                      # Bash scripts (Linux/macOS)
└── README.md                 # This file
```

### Script Categories

#### Management Scripts
- `start.ps1` / `start.sh` - Start the platform
- `stop.ps1` / `stop.sh` - Stop the platform
- `setup.ps1` / `setup.sh` - Initial setup

#### Backup & Recovery
- `backup.ps1` / `backup.sh` - Create backups
- `restore.ps1` / `restore.sh` - Restore from backups
- `backup-scheduler.ps1` / `backup-scheduler.sh` - Automated scheduling

#### Maintenance
- `cleanup.ps1` / `cleanup.sh` - Data cleanup
- `test-connectivity.ps1` / `test-connectivity.sh` - Connectivity testing

---

## 🤝 Contributing

### Development Setup

1. **Fork the repository**
2. **Clone your fork**
   ```bash
   git clone https://github.com/your-username/re-universe.git
   cd re-universe
   ```
3. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. **Make your changes**
5. **Test your changes**
   ```bash
   # Run tests
   ./test-connectivity.sh

   # Create test backup
   ./backup.sh -BackupName "test-feature"
   ```
6. **Submit a pull request**

### Guidelines

- **Cross-platform compatibility** - Test on Windows, Linux, and macOS
- **Documentation** - Update README.md for new features
- **Testing** - Include tests for new functionality
- **Code style** - Follow existing patterns in PowerShell and Bash scripts
- **Commits** - Use descriptive commit messages

### Testing Checklist

- [ ] Scripts work on Windows (PowerShell)
- [ ] Scripts work on Linux (Bash)
- [ ] Scripts work on macOS (Bash)
- [ ] Backup/restore cycle works
- [ ] Cleanup operations work correctly
- [ ] Error handling is robust
- [ ] Documentation is updated

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Ghidra Team** - For the excellent reverse engineering framework
- **ret-sync** - For Ghidra/debugger synchronization
- **x64dbg** - For dynamic analysis capabilities
- **Docker** - For containerization technology

---

## 📞 Support

### Getting Help

1. **Check the documentation** - This README and inline script help
2. **Review logs** - Check `sync-logs/` and Docker logs
3. **Test connectivity** - Run `./test-connectivity.sh`
4. **Check GitHub Issues** - Search existing issues
5. **Create an issue** - For bugs or feature requests

### Useful Commands

```bash
# System status
docker-compose ps
docker stats

# Log analysis
tail -f sync-logs/*.log
docker logs ghidra-server

# Backup management
ls -la backups/*.zip
./backup.sh --help
```

---

*Built with ❤️ for the reverse engineering community*
