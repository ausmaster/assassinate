#!/bin/bash
#
# Manual PostgreSQL Setup (run with your authenticated terminal)
#

set -e

echo "=== Setting up PostgreSQL for Metasploit Tests ==="
echo ""

# Create user and database
echo "Creating database user and database..."
sudo -u postgres psql << 'EOF'
-- Drop existing if needed
DROP DATABASE IF EXISTS metasploit_framework_test;
DROP USER IF EXISTS metasploit_framework_test;

-- Create user
CREATE USER metasploit_framework_test WITH PASSWORD 'metasploit_test_password';

-- Create database
CREATE DATABASE metasploit_framework_test OWNER metasploit_framework_test;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE metasploit_framework_test TO metasploit_framework_test;

-- Connect to the database and grant schema privileges
\c metasploit_framework_test
GRANT ALL ON SCHEMA public TO metasploit_framework_test;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO metasploit_framework_test;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO metasploit_framework_test;

\q
EOF

echo "✓ Database created"
echo ""

# Update pg_hba.conf to allow password authentication for this user
echo "Configuring password authentication..."
PG_HBA=$(sudo -u postgres psql -t -P format=unaligned -c "SHOW hba_file;")
echo "PostgreSQL HBA file: $PG_HBA"

# Backup original
sudo cp "$PG_HBA" "${PG_HBA}.backup.$(date +%Y%m%d_%H%M%S)"

# Add rule for our test user (before other rules)
if ! sudo grep -q "metasploit_framework_test" "$PG_HBA"; then
    sudo sed -i '1i# Metasploit test database' "$PG_HBA"
    sudo sed -i '2ilocal   metasploit_framework_test   metasploit_framework_test   md5' "$PG_HBA"
    sudo sed -i '3ihost    metasploit_framework_test   metasploit_framework_test   127.0.0.1/32   md5' "$PG_HBA"
    sudo sed -i '4ihost    metasploit_framework_test   metasploit_framework_test   ::1/128   md5' "$PG_HBA"
    echo "✓ Updated pg_hba.conf"
else
    echo "✓ pg_hba.conf already configured"
fi

# Reload PostgreSQL
echo "Reloading PostgreSQL..."
sudo systemctl reload postgresql || sudo -u postgres pg_ctl reload

echo "✓ PostgreSQL reloaded"
echo ""

# Test connection
echo "Testing database connection..."
if PGPASSWORD=metasploit_test_password psql -h localhost -U metasploit_framework_test -d metasploit_framework_test -c "SELECT version();" > /dev/null 2>&1; then
    echo "✓ Database connection successful"
else
    echo "✗ Connection test failed"
    exit 1
fi

echo ""
echo "=== Database setup complete! ==="
