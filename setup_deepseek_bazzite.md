# DeepSeek Coder V2.5 16B Setup Guide for Bazzite

This guide will help you set up DeepSeek Coder V2.5 16B (4-bit quantized) on Bazzite (Fedora-based immutable OS).

## Prerequisites Check

First, verify your system setup:

```bash
# Check GPU
nvidia-smi

# Check Python (should be 3.11+)
python3 --version

# Check CUDA availability
nvcc --version  # Optional, not always needed
```

## Method 1: Using Ollama (Easiest - Recommended for Beginners)

Ollama handles model downloads, quantization, and GPU acceleration automatically.

### Step 1: Install Ollama

```bash
# Download and install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Or install via Flatpak (if available)
# flatpak install flathub io.ollama.ollama
```

### Step 2: Start Ollama Service

```bash
# Start the service
systemctl --user enable ollama
systemctl --user start ollama

# Verify it's running
systemctl --user status ollama
```

### Step 3: Pull DeepSeek Coder Model

```bash
# Pull the 16B model (Ollama will automatically use 4-bit quantization)
ollama pull deepseek-coder:16b

# If that doesn't work, try:
ollama pull deepseek-ai/deepseek-coder-v2-lite-instruct:16b

# Or check available models:
ollama list
```

### Step 4: Test the Model

```bash
# Run a test query
ollama run deepseek-coder:16b "Write a Python function to calculate fibonacci numbers"

# Or start interactive mode
ollama run deepseek-coder:16b
```

### Step 5: Configure for API Access (Optional)

Ollama runs a local API server on port 11434. You can use it with Continue.dev or other tools:

```bash
# Test API endpoint
curl http://localhost:11434/api/generate -d '{
  "model": "deepseek-coder:16b",
  "prompt": "Write hello world in Python",
  "stream": false
}'
```

## Method 2: Using vLLM (Best Performance)

vLLM provides faster inference and better memory management.

### Step 1: Install System Dependencies

```bash
# Install Python development tools
sudo rpm-ostree install python3-pip python3-devel gcc gcc-c++ make cmake

# Install CUDA toolkit (if not already installed)
# Check if NVIDIA drivers are installed:
nvidia-smi

# If drivers are missing, install them:
sudo rpm-ostree install akmod-nvidia xorg-x11-drv-nvidia-cuda
# Then reboot
```

### Step 2: Create Python Virtual Environment

```bash
# Create a directory for your LLM setup
mkdir -p ~/llm-setup
cd ~/llm-setup

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip
```

### Step 3: Install vLLM

```bash
# Install vLLM with CUDA support
pip install vllm

# Or install with specific CUDA version (adjust for your CUDA version)
# pip install vllm --extra-index-url https://download.pytorch.org/whl/cu121
```

### Step 4: Download Model (Optional - vLLM can download automatically)

```bash
# Install huggingface-hub for model management
pip install huggingface-hub

# Login to HuggingFace (optional, for gated models)
huggingface-cli login
```

### Step 5: Run vLLM Server

```bash
# Start the server with DeepSeek Coder V2.5 16B
python -m vllm.entrypoints.openai.api_server \
    --model deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct \
    --quantization awq \
    --tensor-parallel-size 1 \
    --gpu-memory-utilization 0.85 \
    --max-model-len 131072 \
    --host 0.0.0.0 \
    --port 8000

# Monitor VRAM usage in another terminal:
watch -n 1 nvidia-smi
```

**Note**: The first run will download the model (~10GB), which may take time.

### Step 6: Test the API

```bash
# Test with curl
curl http://localhost:8000/v1/completions \
    -H "Content-Type: application/json" \
    -d '{
      "model": "deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct",
      "prompt": "def fibonacci(n):",
      "max_tokens": 100,
      "temperature": 0.7
    }'
```

## Method 3: Using llama.cpp (Most Flexible, CPU Fallback)

Good option if you want maximum control and CPU fallback capability.

### Step 1: Install Dependencies

```bash
# Install build dependencies
sudo rpm-ostree install git cmake make gcc gcc-c++ python3-pip

# Reboot if needed after installing packages
```

### Step 2: Clone and Build llama.cpp

```bash
cd ~
git clone https://github.com/ggerganov/llama.cpp.git
cd llama.cpp

# Build with CUDA support
make LLAMA_CUDA=1

# Or build with all optimizations
make LLAMA_CUDA=1 LLAMA_CUBLAS=1 -j$(nproc)
```

### Step 3: Download GGUF Model

```bash
# Install huggingface-cli
pip install huggingface-hub

# Download the GGUF model (4-bit quantized)
# Check HuggingFace for available GGUF files:
# https://huggingface.co/deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct

# Download using huggingface-cli
huggingface-cli download TheBloke/DeepSeek-Coder-V2-Lite-Instruct-GGUF \
    deepseek-coder-v2-lite-instruct.Q4_K_M.gguf \
    --local-dir ~/models \
    --local-dir-use-symlinks False
```

### Step 4: Run llama.cpp

```bash
cd ~/llama.cpp

# Run with GPU acceleration
./llama-cli \
    -m ~/models/deepseek-coder-v2-lite-instruct.Q4_K_M.gguf \
    --ctx-size 131072 \
    --n-gpu-layers 35 \
    --threads 8 \
    --prompt "Write a Python function to reverse a string"

# Interactive mode
./llama-cli \
    -m ~/models/deepseek-coder-v2-lite-instruct.Q4_K_M.gguf \
    --ctx-size 131072 \
    --n-gpu-layers 35 \
    --threads 8 \
    --interactive
```

## Method 4: Using Continue.dev Integration (Recommended for IDE)

Continue.dev is a VS Code/Cursor extension that integrates seamlessly with local models.

### Step 1: Install Continue.dev Extension

1. Open VS Code or Cursor
2. Install the "Continue" extension
3. It will create a `.continue` directory in your workspace

### Step 2: Configure Continue.dev for Ollama

Create or edit `.continue/config.json`:

```json
{
  "models": [
    {
      "title": "DeepSeek Coder 16B (Local)",
      "provider": "ollama",
      "model": "deepseek-coder:16b",
      "apiBase": "http://localhost:11434"
    }
  ],
  "contextProviders": [
    {
      "name": "files",
      "params": {}
    },
    {
      "name": "codebase",
      "params": {
        "maxDepth": 3
      }
    },
    {
      "name": "github",
      "params": {}
    }
  ],
  "embeddingsProvider": {
    "provider": "ollama",
    "model": "nomic-embed-text"
  }
}
```

### Step 3: Pull Embeddings Model (for RAG)

```bash
# Pull embeddings model for codebase search
ollama pull nomic-embed-text
```

### Step 4: Use Continue.dev

1. Open any file in your repository
2. Use `Cmd/Ctrl + L` to open Continue chat
3. Ask questions or request code changes
4. Continue will automatically load relevant context from your codebase

## Verification and Testing

### Test GPU Acceleration

```bash
# Check GPU is being used
nvidia-smi

# Should show your process using GPU memory
```

### Test Model Performance

Create a test script `test_model.py`:

```python
import requests
import json

# Test Ollama API
response = requests.post(
    'http://localhost:11434/api/generate',
    json={
        'model': 'deepseek-coder:16b',
        'prompt': 'Write a Python function to calculate the factorial of a number with proper error handling.',
        'stream': False
    }
)

print(json.dumps(response.json(), indent=2))
```

Run it:
```bash
python3 test_model.py
```

## Troubleshooting

### Issue: "CUDA out of memory"

**Solution**: Reduce context window or use smaller model
```bash
# For vLLM, reduce max-model-len
--max-model-len 65536  # Instead of 131072
```

### Issue: "Model not found" in Ollama

**Solution**: Check available models and pull correct name
```bash
ollama list
ollama search deepseek
```

### Issue: vLLM installation fails

**Solution**: Install specific CUDA version or use pre-built wheels
```bash
# Check CUDA version
nvidia-smi | grep CUDA

# Install matching vLLM version
pip install vllm --extra-index-url https://download.pytorch.org/whl/cu121
```

### Issue: GPU not detected

**Solution**: Verify NVIDIA drivers
```bash
# Check drivers
nvidia-smi

# If missing, install (requires reboot)
sudo rpm-ostree install akmod-nvidia xorg-x11-drv-nvidia-cuda
sudo reboot
```

### Issue: Bazzite immutable filesystem

**Solution**: Use user directory or overlay
```bash
# Work in home directory
cd ~/llm-setup

# Or use rpm-ostree overlay for system packages
sudo rpm-ostree install --allow-inactive <package>
```

## Performance Optimization

### For 16GB VRAM:

1. **Monitor VRAM usage**:
   ```bash
   watch -n 1 nvidia-smi
   ```

2. **Adjust context window** based on available VRAM:
   - 128K tokens: ~6-8GB VRAM (with 10GB model)
   - 64K tokens: ~4-5GB VRAM
   - 32K tokens: ~2-3GB VRAM

3. **Use quantization**: Always use 4-bit (Q4_K_M or AWQ)

4. **Enable flash attention** (if supported):
   ```bash
   # vLLM enables this by default
   # For llama.cpp, it's automatic with CUDA
   ```

## Next Steps

1. **Choose your method**: Ollama (easiest) or vLLM (fastest)
2. **Test with a small code snippet** from your repository
3. **Set up RAG/retrieval** for loading relevant code context
4. **Integrate with your IDE** using Continue.dev

## Quick Start Command Summary

```bash
# Method 1: Ollama (Recommended)
curl -fsSL https://ollama.com/install.sh | sh
systemctl --user enable --now ollama
ollama pull deepseek-coder:16b
ollama run deepseek-coder:16b

# Method 2: vLLM
python3 -m venv ~/llm-setup/venv
source ~/llm-setup/venv/bin/activate
pip install vllm
python -m vllm.entrypoints.openai.api_server \
    --model deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct \
    --quantization awq \
    --gpu-memory-utilization 0.85
```

## Resources

- [Ollama Documentation](https://github.com/ollama/ollama)
- [vLLM Documentation](https://docs.vllm.ai/)
- [llama.cpp GitHub](https://github.com/ggerganov/llama.cpp)
- [Continue.dev Documentation](https://docs.continue.dev/)
- [DeepSeek Coder Models](https://huggingface.co/deepseek-ai)
