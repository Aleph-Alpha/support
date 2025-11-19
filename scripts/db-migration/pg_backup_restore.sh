#!/bin/bash
# pg_backup_restore.sh
# Backup and restore PostgreSQL databases using static credentials from a .env file
# Backup will exclude ownership information

set -e

# Check for psql version 17
check_psql_version() {
    echo "🔧 Checking PostgreSQL client version..."

    if ! command -v psql >/dev/null 2>&1; then
        echo "❌ Error: PostgreSQL client (psql) is not installed." >&2
        echo "💡 Please install PostgreSQL 17 client tools." >&2
        exit 2
    fi

    local version
    version=$(psql --version | awk '{print $3}')
    major_version=$(echo "$version" | cut -d. -f1)

    echo "📋 Found PostgreSQL client version: $version"

    if [ "$major_version" != "17" ]; then
        echo "❌ Error: PostgreSQL client version 17 is required. Found version $version." >&2
        echo "💡 Please install PostgreSQL 17 client tools for compatibility." >&2
        exit 3
    fi

    echo "✅ PostgreSQL client version 17 verified!"
    echo ""
}

# Load environment variables from .env file in the same directory as the script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

echo "🗂️  Loading database configuration from .env file..."

if [ -f "$ENV_FILE" ]; then
    echo "✓ Found .env file at: $ENV_FILE"
    set -a
    # shellcheck source=.env
    source "$ENV_FILE"
    set +a
    echo "✓ Environment variables loaded successfully"
    echo ""
else
    echo "❌ Error: .env file not found at $ENV_FILE" >&2
    echo "💡 Please create a .env file with the required database configuration." >&2
    exit 4
fi

# Validate required environment variables
require_env_vars() {
    local missing=0
    echo "🔍 Validating database configuration..."

    for var in DB_HOST DB_PORT DB_USER DB_PASSWORD DB_NAME; do
        if [ -z "${!var}" ]; then
            echo "❌ Error: $var is not set in .env file." >&2
            missing=1
        else
            if [ "$var" != "DB_PASSWORD" ]; then
                echo "✓ $var: ${!var}"
            else
                echo "✓ $var: [HIDDEN]"
            fi
        fi
    done

    if [ "$missing" -eq 1 ]; then
        echo ""
        echo "❌ Configuration validation failed! Please check your .env file."
        exit 5
    fi

    echo "✅ Database configuration validated successfully!"
    echo ""
}

usage() {
    echo ""
    echo "PostgreSQL Backup & Restore Script"
    echo "----------------------------------"
    echo "Usage:"
    echo "  $0 backup <output_file>   # Create a backup of the database to <output_file>"
    echo "  $0 restore <input_file>   # Restore the database from <input_file>"
    echo ""
    echo "Environment:"
    echo "  Reads DB credentials from .env file in the same directory as this script."
    echo "  .env file must contain:"
    echo "    DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME"
    echo ""
    echo "Examples:"
    echo "  $0 backup backup.sql"
    echo "  $0 restore backup.sql"
    echo ""
    exit 1
}

run_backup() {
    local output_file="$1"
    echo "🔄 Starting database backup operation..."
    echo "📊 Database: $DB_NAME"
    echo "🖥️  Host: $DB_HOST:$DB_PORT"
    echo "👤 User: $DB_USER"
    echo "📁 Output file: $output_file"
    echo ""
    echo "⏳ Running pg_dump (this may take a while for large databases)..."

    PGPASSWORD="$DB_PASSWORD" pg_dump --host="$DB_HOST" --port="$DB_PORT" --username="$DB_USER" --no-owner --format=plain --file="$output_file" "$DB_NAME"

    if [ $? -eq 0 ]; then
        echo "✅ Backup completed successfully!"
        echo "📄 Backup file: $output_file"
        echo "📊 File size: $(du -h "$output_file" | cut -f1)"
    else
        echo "❌ Backup failed! Please check your database connection and permissions." >&2
        exit 6
    fi
}

run_restore() {
    local input_file="$1"

    # Check if input file exists
    if [ ! -f "$input_file" ]; then
        echo "❌ Error: Backup file '$input_file' does not exist!" >&2
        exit 8
    fi

    echo "🔄 Database restore operation"
    echo "📊 Target database: $DB_NAME"
    echo "🖥️ Host: $DB_HOST:$DB_PORT"
    echo "👤 User: $DB_USER"
    echo "📁 Source file: $input_file"
    echo "📊 File size: $(du -h "$input_file" | cut -f1)"
    echo ""
    echo "⚠️  WARNING: This will overwrite all data in the target database!"
    echo ""

    read -p "🤔 Are you sure you want to restore the database '$DB_NAME' from '$input_file'? [y/N]: " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo ""
        echo "⏳ Running database restore (this may take a while for large backups)..."

        PGPASSWORD="$DB_PASSWORD" psql --host="$DB_HOST" --port="$DB_PORT" --username="$DB_USER" --dbname="$DB_NAME" -f "$input_file"

        if [ $? -eq 0 ]; then
            echo ""
            echo "✅ Database restore completed successfully!"
            echo "📊 Database '$DB_NAME' has been restored from '$input_file'"
        else
            echo ""
            echo "❌ Restore failed! Please check the backup file format and database permissions." >&2
            exit 7
        fi
    else
        echo ""
        echo "🚫 Restore operation cancelled by user."
        exit 0
    fi
}

if [ $# -lt 2 ]; then
    usage
fi

echo "🚀 PostgreSQL Backup & Restore Script Starting..."
echo ""

check_psql_version
require_env_vars

COMMAND="$1"
FILE="$2"

echo "📋 Operation requested: $COMMAND"
echo "📁 Target file: $FILE"
echo ""

case "$COMMAND" in
    backup)
        run_backup "$FILE"
        ;;
    restore)
        run_restore "$FILE"
        ;;
    *)
        echo "❌ Error: Unknown command '$COMMAND'" >&2
        usage
        ;;
esac
