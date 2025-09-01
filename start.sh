#!/bin/bash
# RE Analysis Platform - Start Script

echo -e "\033[36mStarting Ghidra Server...\033[0m"
docker-compose up -d

echo -e "\033[33mWaiting for server initialization...\033[0m"
sleep 60

echo -e "\033[36mRunning connectivity tests...\033[0m"
# Test port connectivity
if nc -z Docker 13100 2>/dev/null; then
    echo -e "\033[32m✓ Port 13100 is accessible\033[0m"
else
    echo -e "\033[31m✗ Cannot connect to port 13100\033[0m"
    exit 1
fi

echo -e "\033[32mGhidra Server is ready!\033[0m"
echo -e "\033[33mConnect to: Docker:13100\033[0m"
echo -e "\033[33mCredentials: admin/changeme\033[0m"
