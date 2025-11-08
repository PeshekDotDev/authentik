# Quick Start: DeepSeek Coder V2.5 16B on Bazzite

## Fastest Setup (Ollama - Recommended)

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Start service
systemctl --user enable --now ollama

# 3. Pull model (or use automated script)
ollama pull deepseek-coder:16b

# 4. Test
ollama run deepseek-coder:16b "Write hello world in Python"
```

**Or use the automated script:**
```bash
./setup_ollama_bazzite.sh
```

## Verify Installation

```bash
# Check GPU
nvidia-smi

# Check Ollama
systemctl --user status ollama

# List models
ollama list

# Test model
python3 test_model.py
```

## Common Commands

```bash
# Run model interactively
ollama run deepseek-coder:16b

# Generate code
ollama run deepseek-coder:16b "Your prompt here"

# API endpoint
curl http://localhost:11434/api/generate -d '{
  "model": "deepseek-coder:16b",
  "prompt": "Write a function",
  "stream": false
}'

# Monitor GPU
watch -n 1 nvidia-smi
```

## Troubleshooting

**GPU not detected:**
```bash
sudo rpm-ostree install akmod-nvidia xorg-x11-drv-nvidia-cuda
sudo reboot
```

**Ollama service not starting:**
```bash
systemctl --user restart ollama
journalctl --user -u ollama -f
```

**Model not found:**
```bash
ollama search deepseek
ollama pull deepseek-coder:16b
```

## Full Documentation

See `setup_deepseek_bazzite.md` for complete instructions.
