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
- ⚡ Installable via script, Homebrew (macOS/Linux), or Scoop (Windows)

---

## 🚀 Installation

### Using install script (Linux/macOS)
```bash
curl -fsSL https://raw.githubusercontent.com/dmitrii-kalashnikov/kfast/master/install.sh | bash

