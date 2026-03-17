# 🪜 Burp FlipFlow

**Burp FlipFlow** is a premium request chaining and automation extension for Burp Suite Professional. It enables security testers to build complex, multi-step HTTP workflows with dynamic variable substitution, advanced extraction rules, and protocol-level reliability.

> [!TIP]
> Use FlipFlow to eliminate repetitive manual work in complex testing scenarios like JWT refreshes, multi-stage API chains, and stateful application testing.

---

## ✨ Features

### 🚀 Automation & Chaining
- **Sequential Execution**: Run a series of requests with a single click.
- **Dynamic Variable Substitution**: Use `{{variable_name}}` anywhere in your request (URL, Headers, Body, Host). 
  - **Smart Substitution**: Variables are case-insensitive and support automatic whitespace trimming (e.g., `{{ var }}`).
- **Conditional Post-Actions**: Trigger secondary workflows based on response status (e.g., "Run Login Flow if 401").

### 🔍 Protocol & Reliability
- **Auto Content-Length**: Automatically recalculates the `Content-Length` header if your request body changes—say goodbye to mysterious 400 errors!
- **CRLF Normalization**: Ensures all requests use proper `\r\n` line endings for maximum server compatibility.
- **Response Inspector**: A dedicated tab to view raw Request and Response data for every step in an execution.
- **Auto-clear Logs**: Option to automatically clear logs and inspector data before each execution for a clean workspace.

### 🧬 Powerful Extraction
Extract values from any part of the HTTP response using multiple methods:
- **JSONPath**: Seamless extraction from complex JSON APIs (e.g., `$.data.user_id`).
- **Regex**: High-speed matching with capture groups.
- **Headers**: Grab values from specific response headers (e.g., `Authorization`).
- **Cookies**: Automatically extract session values from `Set-Cookie`.

### 📤 Import & Export
- **JSON Based Sharing**: Export your workflows as `.json` files to share with your team or backup.
- **Seamless Import**: Import workflows with automatic collision handling (deduplication of names).
- **Native Experience**: Integrated with system file dialogs.

---

## 🛠️ Installation

### 1. Requirements
- **Burp Suite Professional**
- **Jython Standalone**: [Download Jython 2.7.x Standalone JAR](https://www.jython.org/download)

### 2. Setup
1. **Configure Jython**: In Burp, go to `Extensions > Options > Python Environment` and set the path to your Jython standalone JAR.
2. **Add Extension**:
   - Go to `Extensions > Installed > Add`.
   - Select Extension type: **Python**.
   - Choose [flipflow.py](flipflow.py).
3. **Done!**: A new `FlipFlow` tab will appear in your Burp Suite window.

---

## 📖 Quick Start

### 1. Create your first Flow
- Click **[+] New** in the left panel.
- Rename your workflow by double-clicking it or using the `Rename` button.

### 2. Add Steps
- **Import from Burp**: Right-click any request in **Proxy History**, **Repeater**, or **Intruder** → `Send to FlipFlow`. 
- **Manual Entry**: Click `Add Step` inside your workflow editor.

### 3. Chain Requests with Variables
1. **Define an Extraction Rule**: In Step 1, click `+` under Extraction Rules. Name it `auth_token`.
2. **Inject the Variable**: In Step 2, edit your request to include `Authorization: Bearer {{auth_token}}`.
3. **Run**: Click **Run Workflow**. Watch the execution log and variables panel update in real-time.

---

## 🔗 Deep Integration

### Context Menus
Right-click any request anywhere in Burp to send it to FlipFlow. It automatically populates Host, Port, HTTPS, and Raw Request fields.

### Session Handling (Intruder/Scanner)
Use FlipFlow as a "Session Handling Action":
1. Go to `Project Options > Sessions > Session Handling Rules > Add`.
2. Select `Invoke a Burp extension` and choose **FlipFlow**.
3. Now, before every request, Burp will check for the `X-FlipFlow-Execute-Before: WorkflowName` header.

### External Triggering
Add `X-FlipFlow-Execute-Before: MyAuthFlow` to any manual request. The extension will run "MyAuthFlow" first and then proceed with your original request—perfect for transparently refreshing tokens in Repeater.

---

## 💾 Storage & Persistence
- Flows are saved automatically to your home directory: `~/.flipflow/`.
- Workflows are stored as human-readable `.json` files.

---

*Built for professional security testers. Optimized for speed, reliability, and ease of use.*
