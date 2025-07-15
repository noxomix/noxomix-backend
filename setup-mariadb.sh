#!/bin/bash

# MariaDB Docker Setup Script
# This script sets up a persistent MariaDB container for the Noxomix backend

set -e

# Configuration
CONTAINER_NAME="noxomix-mariadb"
VOLUME_NAME="noxomix-mariadb-data"
NETWORK_NAME="noxomix-network"
MARIADB_VERSION="11.2"
DB_NAME="noxomix"
DB_USER="noxomix"
DB_PASSWORD="noxomix_secure_password_2024"
DB_ROOT_PASSWORD="root_secure_password_2024"
DB_PORT="3306"

echo "🚀 Setting up MariaDB for Noxomix..."

# Create Docker network if it doesn't exist
if ! docker network ls | grep -q "$NETWORK_NAME"; then
    echo "📡 Creating Docker network: $NETWORK_NAME"
    docker network create "$NETWORK_NAME"
else
    echo "✅ Docker network already exists: $NETWORK_NAME"
fi

# Create volume if it doesn't exist
if ! docker volume ls | grep -q "$VOLUME_NAME"; then
    echo "💾 Creating Docker volume: $VOLUME_NAME"
    docker volume create "$VOLUME_NAME"
else
    echo "✅ Docker volume already exists: $VOLUME_NAME"
fi

# Stop and remove existing container if it exists
if docker ps -a | grep -q "$CONTAINER_NAME"; then
    echo "🛑 Stopping existing container..."
    docker stop "$CONTAINER_NAME" 2>/dev/null || true
    docker rm "$CONTAINER_NAME" 2>/dev/null || true
fi

# Pull the latest MariaDB image
echo "📦 Pulling MariaDB image..."
docker pull "mariadb:$MARIADB_VERSION"

# Run MariaDB container
echo "🏃 Starting MariaDB container..."
docker run -d \
    --name "$CONTAINER_NAME" \
    --network "$NETWORK_NAME" \
    -p "$DB_PORT:3306" \
    -v "$VOLUME_NAME:/var/lib/mysql" \
    -e "MYSQL_ROOT_PASSWORD=$DB_ROOT_PASSWORD" \
    -e "MYSQL_DATABASE=$DB_NAME" \
    -e "MYSQL_USER=$DB_USER" \
    -e "MYSQL_PASSWORD=$DB_PASSWORD" \
    --restart unless-stopped \
    "mariadb:$MARIADB_VERSION"

echo "⏳ Waiting for MariaDB to be ready..."
sleep 10

# Check if MariaDB is running
if docker ps | grep -q "$CONTAINER_NAME"; then
    echo "✅ MariaDB is running!"
    echo ""
    echo "📋 Connection Details:"
    echo "   Host: localhost"
    echo "   Port: $DB_PORT"
    echo "   Database: $DB_NAME"
    echo "   Username: $DB_USER"
    echo "   Password: $DB_PASSWORD"
    echo "   Root Password: $DB_ROOT_PASSWORD"
    echo ""
    echo "🔗 Connection URL for .env:"
    echo "   DATABASE_URL=mysql://$DB_USER:$DB_PASSWORD@localhost:$DB_PORT/$DB_NAME"
    echo ""
    echo "📝 To connect with mysql client:"
    echo "   docker exec -it $CONTAINER_NAME mysql -u$DB_USER -p$DB_PASSWORD $DB_NAME"
else
    echo "❌ Failed to start MariaDB container"
    exit 1
fi

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file..."
    cat > .env << EOF
# Database Configuration
DATABASE_URL=mysql://$DB_USER:$DB_PASSWORD@localhost:$DB_PORT/$DB_NAME
DATABASE_HOST=localhost
DATABASE_PORT=$DB_PORT
DATABASE_NAME=$DB_NAME
DATABASE_USER=$DB_USER
DATABASE_PASSWORD=$DB_PASSWORD

# Server Configuration
PORT=3000
HOST=0.0.0.0
EOF
    echo "✅ .env file created"
else
    echo "ℹ️  .env file already exists, please update DATABASE_URL manually"
fi

echo ""
echo "🎉 MariaDB setup complete!"
echo ""
echo "📌 Useful commands:"
echo "   Stop:    docker stop $CONTAINER_NAME"
echo "   Start:   docker start $CONTAINER_NAME"
echo "   Logs:    docker logs $CONTAINER_NAME"
echo "   Shell:   docker exec -it $CONTAINER_NAME bash"
echo "   MySQL:   docker exec -it $CONTAINER_NAME mysql -uroot -p$DB_ROOT_PASSWORD"