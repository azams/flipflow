# 🪜 Burp FlipFlow

**Burp FlipFlow** is a powerful request chaining and automation extension for Burp Suite Professional. It allows security testers to build complex, multi-step HTTP workflows with dynamic variable substitution, advanced extraction rules, and protocol-level reliability.

> [!TIP]
> Use FlipFlow to eliminate repetitive manual work in complex testing scenarios like JWT refreshes, multi-stage API chains, and stateful application testing.

---

## ✨ Features

### 🚀 Automation & Chaining
- **Sequential Execution**: Run a series of requests with a single click.
- **Dynamic Variable Substitution**: Use `{{variable_name}}` anywhere in your request (URL, Headers, Body, Host). 
  - *New*: Variables are now case-insensitive and support automatic whitespace trimming (e.g., `{{ var }}`).
- **Conditional Post-Actions**: Trigger secondary workflows based on response status (e.g., "Run Login Flow if 401").

### 🔍 Protocol & Reliability (New!)
- **Auto Content-Length**: Automatically recalculates the `Content-Length` header if your request body changes due to variable substitution—say goodbye to mysterious 400 errors!
- **CRLF Normalization**: Ensures all requests are normalized to use proper `\r\n` line endings for maximum server compatibility.
- **Response Inspector**: A dedicated tab to view raw Request and Response data for every step in an execution, using Burp's familiar message editor.

### 🧬 Powerful Extraction
Extract values from any part of the HTTP response:
- **Regex**: High-speed matching with capture groups.
- **JSONPath**: Seamless extraction from complex JSON APIs (e.g., `$.user.profiles[0].id`).
- **Headers**: Grab values from specific response headers.
- **Cookies**: Automatically extract and store session values from `Set-Cookie`.

---

## 🛠️ Installation

### 1. Requirements
- **Burp Suite Professional**
- **Jython Standalone**: [Download Jython 2.7.x Standalone JAR](https://www.jython.org/download)

### 2. Setup
1. **Configure Jython**: In Burp, go to `Extensions > Options > Python Environment` and set the path to your Jython standalone JAR.
2. **Add Extension**:
   - Go to `Extensions > Installed > Add`.
   - Choose [flipflow.py](flipflow.py).
3. **Done!**: A new `FlipFlow` tab will appear in your Burp Suite window.

---

## 📖 Quick Start

### 1. Create your first Flow
- Click **[+] New** in the left panel.
- Rename your workflow by double-clicking it or using the `Rename` context menu.

### 2. Add Steps
- **Import from Burp**: Right-click any request in **Proxy History**, **Repeater**, or **Intruder** → `Send to FlipFlow`. 
- **Manual Entry**: Click `Add Step` inside your workflow.

### 3. Chain Requests with Variables
1. **Define an Extraction Rule**: In Step 1, click `+` under Extraction Rules. Name it `jwt_token`.
2. **Inject the Variable**: In Step 2, edit your request to include `Authorization: Bearer {{jwt_token}}`.
3. **Run**: Click **Run Workflow**. Watch the execution log and variables panel update in real-time.

---

## 🔗 Deep Integration

### Context Menu
Right-click any request anywhere in Burp to send it to FlipFlow. It will automatically populate the Host, Port, HTTPS, and Raw Request fields.

### Session Handling (Intruder/Scanner)
You can use FlipFlow as a "Session Handling Action":
1. Go to `Project Options > Sessions > Session Handling Rules > Add`.
2. Select `Invoke a Burp extension`.
3. Select **FlipFlow**.
4. Now, before every request sent by Intruder or Scanner, Burp will check for the `X-FlipFlow-Execute-Before` header and run the specified workflow if found.

### External Triggering
Add the header `X-FlipFlow-Execute-Before: MyTokenFlow` to any manual request. The extension will intercept this, run "MyTokenFlow", and proceed with your original request—perfect for transparently refreshing tokens in Repeater.

---

## 💾 Storage & Persistence
- Flows are saved automatically to your home directory: `~/.flipflow/`.
- Workflows are stored as human-readable `.json` files, making them easy to version control or share with team members.

---

*Built for professional security testers. Optimized for speed, reliability, and ease of use.*
