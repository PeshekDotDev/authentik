#!/usr/bin/env python3
"""
Test script for DeepSeek Coder model setup.
Tests both Ollama and vLLM endpoints.
"""

import requests
import json
import sys
import time
from typing import Optional

def test_ollama(model_name: str = "deepseek-coder:16b", host: str = "localhost", port: int = 11434):
    """Test Ollama API endpoint."""
    print("=" * 60)
    print("Testing Ollama API")
    print("=" * 60)
    
    url = f"http://{host}:{port}/api/generate"
    
    test_prompt = """Write a Python function that:
1. Takes a list of numbers as input
2. Returns the sum of all even numbers
3. Includes proper type hints and docstring"""
    
    payload = {
        "model": model_name,
        "prompt": test_prompt,
        "stream": False,
        "options": {
            "temperature": 0.7,
            "num_predict": 200
        }
    }
    
    try:
        print(f"Connecting to {url}...")
        print(f"Model: {model_name}")
        print(f"Prompt: {test_prompt[:50]}...")
        print()
        
        start_time = time.time()
        response = requests.post(url, json=payload, timeout=120)
        elapsed_time = time.time() - start_time
        
        if response.status_code == 200:
            result = response.json()
            print("✓ Success!")
            print(f"Response time: {elapsed_time:.2f}s")
            print()
            print("Generated code:")
            print("-" * 60)
            print(result.get('response', 'No response field'))
            print("-" * 60)
            return True
        else:
            print(f"✗ Error: HTTP {response.status_code}")
            print(response.text)
            return False
            
    except requests.exceptions.ConnectionError:
        print("✗ Connection failed. Is Ollama running?")
        print("  Start with: systemctl --user start ollama")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_vllm(model_name: str = "deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct", 
              host: str = "localhost", port: int = 8000):
    """Test vLLM OpenAI-compatible API endpoint."""
    print("=" * 60)
    print("Testing vLLM API")
    print("=" * 60)
    
    url = f"http://{host}:{port}/v1/completions"
    
    test_prompt = """Write a Python function that:
1. Takes a list of numbers as input
2. Returns the sum of all even numbers
3. Includes proper type hints and docstring"""
    
    payload = {
        "model": model_name,
        "prompt": test_prompt,
        "max_tokens": 200,
        "temperature": 0.7
    }
    
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        print(f"Connecting to {url}...")
        print(f"Model: {model_name}")
        print(f"Prompt: {test_prompt[:50]}...")
        print()
        
        start_time = time.time()
        response = requests.post(url, json=payload, headers=headers, timeout=120)
        elapsed_time = time.time() - start_time
        
        if response.status_code == 200:
            result = response.json()
            print("✓ Success!")
            print(f"Response time: {elapsed_time:.2f}s")
            print()
            print("Generated code:")
            print("-" * 60)
            if 'choices' in result and len(result['choices']) > 0:
                print(result['choices'][0]['text'])
            else:
                print(json.dumps(result, indent=2))
            print("-" * 60)
            return True
        else:
            print(f"✗ Error: HTTP {response.status_code}")
            print(response.text)
            return False
            
    except requests.exceptions.ConnectionError:
        print("✗ Connection failed. Is vLLM server running?")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def check_gpu():
    """Check GPU status."""
    print("=" * 60)
    print("GPU Status")
    print("=" * 60)
    
    try:
        import subprocess
        result = subprocess.run(['nvidia-smi', '--query-gpu=name,memory.used,memory.total,utilization.gpu', 
                                '--format=csv,noheader'], 
                               capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(result.stdout)
            return True
        else:
            print("nvidia-smi not available")
            return False
    except Exception as e:
        print(f"Could not check GPU: {e}")
        return False

def main():
    """Main test function."""
    print("\n" + "=" * 60)
    print("DeepSeek Coder V2.5 16B Model Test")
    print("=" * 60 + "\n")
    
    # Check GPU
    check_gpu()
    print()
    
    # Test Ollama (default)
    ollama_success = test_ollama()
    print()
    
    # Test vLLM (optional)
    if len(sys.argv) > 1 and sys.argv[1] == "--test-vllm":
        vllm_success = test_vllm()
        print()
    
    # Summary
    print("=" * 60)
    print("Test Summary")
    print("=" * 60)
    if ollama_success:
        print("✓ Ollama: Working")
    else:
        print("✗ Ollama: Failed")
    
    if len(sys.argv) > 1 and sys.argv[1] == "--test-vllm":
        if vllm_success:
            print("✓ vLLM: Working")
        else:
            print("✗ vLLM: Failed")
    
    print()
    print("For more information, see: setup_deepseek_bazzite.md")

if __name__ == "__main__":
    main()
