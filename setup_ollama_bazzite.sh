#!/bin/bash
# Quick setup script for Ollama on Bazzite
# This script automates the Ollama installation and DeepSeek Coder setup

set -e

echo "=========================================="
echo "DeepSeek Coder V2.5 16B Setup for Bazzite"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if running on Bazzite
if [ ! -f /etc/os-release ]; then
    echo -e "${RED}Error: Cannot detect OS${NC}"
    exit 1
fi

# Check GPU
echo -e "${YELLOW}Step 1: Checking GPU...${NC}"
if command -v nvidia-smi &> /dev/null; then
    echo -e "${GREEN}✓ NVIDIA GPU detected${NC}"
    nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
else
    echo -e "${RED}✗ NVIDIA GPU not detected. Make sure drivers are installed.${NC}"
    echo "Install with: sudo rpm-ostree install akmod-nvidia xorg-x11-drv-nvidia-cuda"
    exit 1
fi

# Check if Ollama is installed
echo ""
echo -e "${YELLOW}Step 2: Checking Ollama installation...${NC}"
if command -v ollama &> /dev/null; then
    echo -e "${GREEN}✓ Ollama is already installed${NC}"
    ollama --version
else
    echo -e "${YELLOW}Installing Ollama...${NC}"
    curl -fsSL https://ollama.com/install.sh | sh
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Ollama installed successfully${NC}"
    else
        echo -e "${RED}✗ Failed to install Ollama${NC}"
        exit 1
    fi
fi

# Start Ollama service
echo ""
echo -e "${YELLOW}Step 3: Starting Ollama service...${NC}"
systemctl --user enable ollama 2>/dev/null || true
systemctl --user start ollama

# Wait for service to be ready
echo "Waiting for Ollama to start..."
sleep 3

if systemctl --user is-active --quiet ollama; then
    echo -e "${GREEN}✓ Ollama service is running${NC}"
else
    echo -e "${RED}✗ Ollama service failed to start${NC}"
    echo "Check status with: systemctl --user status ollama"
    exit 1
fi

# Check available models
echo ""
echo -e "${YELLOW}Step 4: Checking available models...${NC}"
ollama list

# Pull DeepSeek Coder model
echo ""
echo -e "${YELLOW}Step 5: Downloading DeepSeek Coder V2.5 16B model...${NC}"
echo "This may take several minutes (~10GB download)..."
echo ""

# Try different model names
MODEL_PULLED=false

for model_name in "deepseek-coder:16b" "deepseek-ai/deepseek-coder-v2-lite-instruct:16b" "deepseek-coder"; do
    echo "Trying model: $model_name"
    if ollama pull "$model_name" 2>&1 | grep -q "success\|pulling"; then
        echo -e "${GREEN}✓ Successfully pulled model: $model_name${NC}"
        MODEL_PULLED=true
        FINAL_MODEL="$model_name"
        break
    fi
done

if [ "$MODEL_PULLED" = false ]; then
    echo -e "${YELLOW}Could not find exact model name. Searching...${NC}"
    ollama search deepseek
    echo ""
    echo -e "${YELLOW}Please manually pull the model with:${NC}"
    echo "  ollama pull deepseek-coder:16b"
    echo "Or check available models with: ollama list"
    exit 1
fi

# Test the model
echo ""
echo -e "${YELLOW}Step 6: Testing the model...${NC}"
echo "Running a simple test query..."
echo ""

TEST_PROMPT="Write a Python function to add two numbers"
echo "Prompt: $TEST_PROMPT"
echo ""

ollama run "$FINAL_MODEL" "$TEST_PROMPT" --verbose 2>&1 | head -20

if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ Model is working correctly!${NC}"
else
    echo -e "${YELLOW}⚠ Model test had issues, but installation may still be correct${NC}"
fi

# Display usage information
echo ""
echo "=========================================="
echo -e "${GREEN}Setup Complete!${NC}"
echo "=========================================="
echo ""
echo "Usage examples:"
echo "  ollama run $FINAL_MODEL 'Your prompt here'"
echo ""
echo "API endpoint:"
echo "  http://localhost:11434/api/generate"
echo ""
echo "Test API with:"
echo "  curl http://localhost:11434/api/generate -d '{\"model\": \"$FINAL_MODEL\", \"prompt\": \"Hello\", \"stream\": false}'"
echo ""
echo "Monitor GPU usage:"
echo "  watch -n 1 nvidia-smi"
echo ""
echo "For IDE integration (Continue.dev), use model name: $FINAL_MODEL"
echo ""
