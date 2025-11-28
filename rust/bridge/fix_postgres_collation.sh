#!/bin/bash
#
# Fix PostgreSQL Collation Version Mismatch
#
# This happens after system updates that change glibc/ICU versions
#

set -e

echo "=== Fixing PostgreSQL Collation Version Mismatch ==="
echo ""

echo "Refreshing collation versions for template databases..."
sudo -u postgres psql << 'EOF'
-- Refresh postgres database
ALTER DATABASE postgres REFRESH COLLATION VERSION;

-- Refresh template1 database
ALTER DATABASE template1 REFRESH COLLATION VERSION;

-- Reindex everything to be safe
REINDEX DATABASE postgres;
REINDEX DATABASE template1;

\q
EOF

echo "✓ Collation versions refreshed"
echo ""
echo "You can now run ./setup_db_manual.sh again"
