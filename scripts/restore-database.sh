#!/bin/bash

# Database Restore Script
# This script drops and recreates the BSim database from backup
# Use this when you need to restore the database to a known good state
# or recover from database corruption issues

set -e

BACKUP_FILE="/home/ben/re-universe/backups/bsim_backup_2025-02-03.sql"
DB_NAME="bsim"
DB_USER="ben"
DB_PASSWORD="***REDACTED***"
DB_HOST="localhost"
DB_PORT="5432"

echo "🔄 Starting database restore process..."

# Check if backup file exists
if [ ! -f "$BACKUP_FILE" ]; then
    echo "❌ Backup file not found: $BACKUP_FILE"
    exit 1
fi

echo "📋 Stopping dependent services..."
docker-compose stop ai-orchestration github-mining web

echo "🗑️ Dropping existing database..."
PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d postgres -c "DROP DATABASE IF EXISTS $DB_NAME;"

echo "🆕 Creating new database..."
PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d postgres -c "CREATE DATABASE $DB_NAME;"

echo "📦 Adding pgvector extension..."
PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -c "CREATE EXTENSION IF NOT EXISTS vector;"

echo "🔄 Restoring database from backup..."
PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME < "$BACKUP_FILE"

echo "🚀 Restarting all services..."
docker-compose up -d

echo "⏳ Waiting for services to start..."
sleep 30

echo "✅ Verifying database restore..."
function_count=$(PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -t -c "SELECT COUNT(*) FROM functiontable;" | xargs)

if [ "$function_count" -gt 0 ]; then
    echo "✅ Database restore successful! Functions restored: $function_count"
    echo "🔍 Running health check..."
    ./health-check.sh
else
    echo "❌ Database restore failed - no functions found"
    exit 1
fi

echo "🎉 Database restore completed successfully!"