#!/bin/bash
set -e

echo "PATHS - Setup Verification"
echo "============================================"
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0

# Check Python
echo -n "Checking Python 3... "
if command -v python3 &> /dev/null; then
    PY_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN} Found ${PY_VERSION}${NC}"
else
    echo -e "${RED} Not found${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check SWI-Prolog
echo -n "Checking SWI-Prolog... "
if command -v swipl &> /dev/null; then
    echo -e "${GREEN} Found${NC}"
else
    echo -e "${YELLOW} Not found (required for local execution)${NC}"
fi

# Check Graphviz
echo -n "Checking Graphviz... "
if command -v dot &> /dev/null; then
    echo -e "${GREEN} Found${NC}"
else
    echo -e "${YELLOW} Not found (optional for enhanced layouts)${NC}"
fi

# Check Docker
echo -n "Checking Docker... "
if command -v docker &> /dev/null; then
    echo -e "${GREEN} Found${NC}"
    DOCKER_AVAILABLE=1
else
    echo -e "${YELLOW} Not found (Docker support unavailable)${NC}"
    DOCKER_AVAILABLE=0
fi

# Check Virtual Environment
echo -n "Checking virtual environment... "
if [ -d "venv" ]; then
    echo -e "${GREEN} Exists${NC}"
else
    echo -e "${YELLOW} Creating...${NC}"
    python3 -m venv venv
fi

# Activate venv
if source venv/bin/activate 2>/dev/null; then
    echo -e "${GREEN} Virtual environment activated${NC}"
else
    echo -e "${RED} Failed to activate${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Update pip
echo -n "Updating pip... "
pip install --upgrade pip setuptools wheel > /dev/null 2>&1
echo -e "${GREEN} Updated${NC}"

# Install dependencies
echo -n "Installing dependencies... "
pip install -q -r requirements.txt
echo -e "${GREEN} Installed${NC}"

echo ""
echo "============================================"
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN} Setup complete!${NC}"
    echo ""
    if [ $DOCKER_AVAILABLE -eq 1 ]; then
        echo "Run with Docker:"
        echo "  docker-compose up --build"
        echo ""
    fi
    echo "Run locally:"
    echo "  ./start.sh"
    exit 0
else
    echo -e "${RED} $ERRORS error(s) found${NC}"
    exit 1
fi
