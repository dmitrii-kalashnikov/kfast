# kfast

**kfast** is a fast and lightweight Kubernetes troubleshooting CLI tool written in Go.  
It helps you quickly detect cluster issues such as pod failures, CrashLoopBackOffs, misconfigurations, missing resources, and more — all in a single command.

---

## ✨ Features
- 🔍 Cluster health scan in seconds  
- 📊 Clear table output with severity indicators (Critical/Warning/OK)  
- 🚨 Detects common issues:
  - CrashLoopBackOff
  - ImagePullBackOff
  - Scheduling errors
  - Resource quota violations
  - Certificate issues
  - And more…
- 🖥️ Cross-platform: Linux, macOS, Windows  
- ⚡ Multiple installation methods (script, Makefile, Homebrew, PowerShell)

---

## 🚀 Installation

You can install `kfast` in several ways:

### 1. Quick Install (Linux/macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/dmitrii-kalashnikov/kfast/main/install.sh | bash

### 2. Manual Install from Source (Linux/macOS)

```bash
git clone https://github.com/dmitrii-kalashnikov/kfast.git
cd kfast
sudo make install

### 3. Uninstall

```bash
sudo make uninstall

### 🔧 Usage
kfast --help
