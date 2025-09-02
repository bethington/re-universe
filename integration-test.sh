#!/bin/bash
# Integration Test Script for Ghidra RE Platform
# Tests the complete platform workflow from setup to operation

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Test configuration
TEST_BACKUP_NAME="integration-test-$(date +%Y%m%d-%H%M%S)"
CLEANUP_ON_EXIT=true

# Cleanup function
cleanup() {
    if [[ "$CLEANUP_ON_EXIT" == "true" ]]; then
        echo -e "\n${YELLOW}Cleaning up integration test...${NC}"
        ./stop.sh >/dev/null 2>&1 || true
        docker-compose down --volumes --remove-orphans >/dev/null 2>&1 || true
        
        # Remove test backup if it exists
        rm -f "backups/${TEST_BACKUP_NAME}.zip" 2>/dev/null || true
        
        echo -e "${GREEN}Cleanup completed${NC}"
    fi
}

# Set up cleanup trap
trap cleanup EXIT

echo -e "${CYAN}=== Ghidra RE Platform - Integration Test Suite ===${NC}"
echo -e "Testing complete platform workflow...\n"

# Test 1: Environment Setup
echo -e "${CYAN}[1/8] Testing Environment Setup${NC}"
if ./setup.sh >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Environment setup successful${NC}"
else
    echo -e "${RED}❌ Environment setup failed${NC}"
    exit 1
fi

# Test 2: Configuration Management
echo -e "${CYAN}[2/8] Testing Configuration Management${NC}"
if ./config.sh -Action validate >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Configuration validation successful${NC}"
else
    echo -e "${RED}❌ Configuration validation failed${NC}"
    exit 1
fi

# Test 3: Platform Startup
echo -e "${CYAN}[3/8] Testing Platform Startup${NC}"
if ./start.sh >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Platform startup successful${NC}"
    sleep 30  # Allow services to fully initialize
else
    echo -e "${RED}❌ Platform startup failed${NC}"
    exit 1
fi

# Test 4: Connectivity Verification
echo -e "${CYAN}[4/8] Testing Connectivity${NC}"
if ./test-connectivity.sh >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Connectivity test successful${NC}"
else
    echo -e "${RED}❌ Connectivity test failed${NC}"
    exit 1
fi

# Test 5: Backup Creation
echo -e "${CYAN}[5/8] Testing Backup System${NC}"
# Create some test data first
echo "integration test data" > "repo-data/integration-test.txt"

if ./backup.sh -BackupName "$TEST_BACKUP_NAME" >/dev/null 2>&1; then
    if [[ -f "backups/${TEST_BACKUP_NAME}.zip" ]]; then
        echo -e "${GREEN}✅ Backup creation successful${NC}"
    else
        echo -e "${RED}❌ Backup file not created${NC}"
        exit 1
    fi
else
    echo -e "${RED}❌ Backup creation failed${NC}"
    exit 1
fi

# Test 6: Platform Restart
echo -e "${CYAN}[6/8] Testing Platform Restart${NC}"
if ./stop.sh >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Platform shutdown successful${NC}"
    sleep 10
    
    if ./start.sh >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Platform restart successful${NC}"
        sleep 30
    else
        echo -e "${RED}❌ Platform restart failed${NC}"
        exit 1
    fi
else
    echo -e "${RED}❌ Platform shutdown failed${NC}"
    exit 1
fi

# Test 7: Backup Restoration
echo -e "${CYAN}[7/8] Testing Backup Restoration${NC}"
# Remove test data to simulate data loss
rm -f "repo-data/integration-test.txt"

# Stop platform for restore
./stop.sh >/dev/null 2>&1 || true
sleep 5

if ./restore.sh -BackupFile "backups/${TEST_BACKUP_NAME}.zip" --force >/dev/null 2>&1; then
    # Restart platform to verify restore
    ./start.sh >/dev/null 2>&1
    sleep 30
    
    # Check if test data was restored
    if [[ -f "repo-data/integration-test.txt" ]]; then
        echo -e "${GREEN}✅ Backup restoration successful${NC}"
    else
        echo -e "${RED}❌ Backup restoration failed - test data not found${NC}"
        exit 1
    fi
else
    echo -e "${RED}❌ Backup restoration command failed${NC}"
    exit 1
fi

# Test 8: Cleanup Validation
echo -e "${CYAN}[8/8] Testing Cleanup System${NC}"
if ./cleanup.sh --dry-run >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Cleanup dry run successful${NC}"
else
    echo -e "${RED}❌ Cleanup dry run failed${NC}"
    exit 1
fi

# Final connectivity test
echo -e "${CYAN}Final Connectivity Verification${NC}"
if ./test-connectivity.sh >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Final connectivity test successful${NC}"
else
    echo -e "${RED}❌ Final connectivity test failed${NC}"
    exit 1
fi

# Integration test summary
echo -e "\n${GREEN}🎉 Integration Test Suite PASSED${NC}"
echo -e "${WHITE}All 8 test categories completed successfully:${NC}"
echo -e "  ✅ Environment Setup"
echo -e "  ✅ Configuration Management"
echo -e "  ✅ Platform Startup"
echo -e "  ✅ Connectivity Verification"
echo -e "  ✅ Backup Creation"
echo -e "  ✅ Platform Restart"
echo -e "  ✅ Backup Restoration"
echo -e "  ✅ Cleanup Validation"

echo -e "\n${CYAN}Platform is fully operational and ready for production use!${NC}"
