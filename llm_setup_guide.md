# LLM Setup Guide for Code Generation

## Repository Overview
- **Total Size**: 543MB
- **Source Code**: ~2.3MB
- **Total Code Files**: 2,645 files
- **Lines of Code**: ~243,000 lines
- **Languages**: 
  - Python: 1,744 files (Django backend)
  - TypeScript: 697 files (React frontend)
  - Go: 159 files (outpost services)
  - JavaScript: 41 files

## Recommended Models for RTX 5080 (16GB VRAM)

### Option 1: DeepSeek Coder V2.5 16B (Recommended)
- **VRAM Usage**: ~10GB (4-bit quantized)
- **Context Window**: 128K tokens
- **Best for**: High-quality code generation with large context
- **Headroom**: ~6GB for context and system overhead
- **Download**: `deepseek-ai/DeepSeek-Coder-V2-Lite-Base` or `deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct`

### Option 2: CodeLlama 2 13B (4-bit)
- **VRAM Usage**: ~7-8GB (4-bit quantized)
- **Context Window**: 16K tokens
- **Best for**: Proven code generation with good VRAM headroom
- **Headroom**: ~8GB for context and system overhead

### Option 3: DeepSeek Coder 6.7B (4-bit)
- **VRAM Usage**: ~4-5GB (4-bit quantized)
- **Context Window**: 64K tokens
- **Best for**: Fast inference with maximum context headroom
- **Headroom**: ~11GB - allows for very large context windows

### Option 4: Qwen2.5 Coder 7B (4-bit)
- **VRAM Usage**: ~4-5GB (4-bit quantized)
- **Context Window**: 128K tokens
- **Best for**: Large context windows with efficient VRAM usage
- **Headroom**: ~11GB

### Option 5: StarCoder2 15B (4-bit)
- **VRAM Usage**: ~8-9GB (4-bit quantized)
- **Context Window**: 16K tokens
- **Best for**: Code completion and generation tasks
- **Headroom**: ~7GB

### ⚠️ Models That Won't Fit:
- Qwen2.5 Coder 32B (~20GB) - Too large
- CodeLlama 2 34B (~20GB) - Too large
- DeepSeek Coder V2.5 32B (~20GB) - Too large

## Setup Instructions

### 1. Install Dependencies

```bash
# Install Ollama (easiest option)
curl -fsSL https://ollama.com/install.sh | sh

# OR install vLLM for faster inference
pip install vllm

# OR install llama.cpp for CPU/GPU inference
git clone https://github.com/ggerganov/llama.cpp
cd llama.cpp
make
```

### 2. Using Ollama (Recommended for Beginners)

```bash
# Pull the model
ollama pull deepseek-coder:latest

# Or for specific version
ollama pull deepseek-coder:6.7b-instruct-q4_K_M

# Run with context
ollama run deepseek-coder:latest
```

### 3. Using vLLM (Best Performance)

```bash
# Install
pip install vllm

# Run with 4-bit quantization (for 16GB VRAM, use 0.85 to leave headroom)
python -m vllm.entrypoints.openai.api_server \
    --model deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct \
    --quantization awq \
    --tensor-parallel-size 1 \
    --gpu-memory-utilization 0.85 \
    --max-model-len 131072
```

**Note for 16GB VRAM**: Use `--gpu-memory-utilization 0.85` (instead of 0.9) to leave headroom for context tokens and avoid OOM errors.

### 4. Using llama.cpp (Most Flexible)

```bash
# Download GGUF model from HuggingFace
# Example: https://huggingface.co/TheBloke/DeepSeek-Coder-V2-Lite-Instruct-GGUF

# Run with GPU acceleration
./llama-cli -m model.gguf \
    --ctx-size 131072 \
    --n-gpu-layers 35 \
    --threads 8 \
    --prompt "Your code generation prompt here"
```

### 5. Loading Repository Context

For code generation, you'll want to load relevant files into context. Here's a Python script to help:

```python
import os
from pathlib import Path

def load_repository_context(repo_path, max_files=100):
    """Load repository files into a context string."""
    context = []
    code_extensions = {'.py', '.ts', '.js', '.tsx', '.go'}
    
    for root, dirs, files in os.walk(repo_path):
        # Skip common directories
        dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', '.venv'}]
        
        for file in files:
            if Path(file).suffix in code_extensions:
                file_path = Path(root) / file
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        context.append(f"# File: {file_path.relative_to(repo_path)}\n{content}\n")
                        if len(context) >= max_files:
                            return '\n'.join(context)
                except Exception as e:
                    continue
    
    return '\n'.join(context)

# Usage
repo_context = load_repository_context('/workspace', max_files=50)
```

## Context Window Considerations

With ~243,000 lines of code:
- **Average**: ~50-100 tokens per line
- **Total tokens**: ~12-24M tokens (uncompressed)
- **128K context models**: Can fit ~1,000-2,000 lines at once (~0.8% of codebase)
- **Strategy**: **CRITICAL** - You MUST use RAG/retrieval to load relevant files
  - Loading the entire repo is impossible in a single context window
  - Use semantic search to find relevant code sections
  - Load only the files/modules related to your current task

## Recommended Workflow

1. **Use RAG/Retrieval**: Don't load entire repo at once
   - Use embeddings to find relevant files
   - Load only contextually relevant code

2. **Chunking Strategy**:
   - Load related modules together
   - Focus on the specific area you're working on
   - Use file structure to guide context selection

3. **Tools to Consider**:
   - **LlamaIndex**: For RAG and retrieval
   - **LangChain**: For chaining operations
   - **Continue.dev**: IDE extension for code generation
   - **Codeium**: Another IDE extension option

## Example: Setting up with Continue.dev

```bash
# Install Continue.dev extension in VS Code/Cursor
# Configure in .continue/config.json:

{
  "models": [
    {
      "title": "DeepSeek Coder (Local)",
      "provider": "ollama",
      "model": "deepseek-coder:latest",
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
    }
  ]
}
```

## Performance Tips for 16GB VRAM

1. **Use 4-bit quantization** (AWQ, GPTQ, or GGUF Q4_K_M) - Essential for fitting models
2. **Monitor VRAM usage closely**: `watch -n 1 nvidia-smi`
3. **Start conservative**: Use `--gpu-memory-utilization 0.85` to avoid OOM
4. **Adjust context window dynamically**: Larger contexts use more VRAM
5. **Use flash attention** if supported (reduces VRAM usage)
6. **Consider smaller models** (6.7B-7B) if you need very large contexts (>64K tokens)
7. **Batch requests carefully**: Each request adds to VRAM usage
8. **Watch for memory fragmentation**: Restart the server if VRAM usage grows unexpectedly

## Next Steps

1. Choose your model and setup method
2. Test with a small code snippet first
3. Gradually increase context size
4. Implement RAG for better context management
5. Fine-tune prompts for your specific codebase style
