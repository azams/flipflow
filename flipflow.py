# -*- coding: utf-8 -*-
"""
Burp FlipFlow — Multi-Step Request Automation Extension
Python/Jython extension for Burp Suite Professional
"""

from burp import IBurpExtender, ITab, IContextMenuFactory, IHttpListener, ISessionHandlingAction
from burp import IMessageEditorController
from javax.swing import (
    JPanel, JList, JButton, JLabel, JTextField, JTextArea, JScrollPane,
    JSplitPane, JTabbedPane, JTable, JOptionPane, JComboBox, JCheckBox,
    JDialog, JMenu, JMenuItem, JPopupMenu, JFileChooser, BorderFactory, DefaultListModel,
    ListSelectionModel, SwingConstants, SwingUtilities, BoxLayout,
    AbstractListModel, Box
)
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing.table import DefaultTableModel, AbstractTableModel
from javax.swing.event import ListSelectionListener
from java.awt import (
    BorderLayout, GridBagLayout, GridBagConstraints, FlowLayout,
    Dimension, Color, Font, Insets, GridLayout, Component
)
from java.awt.event import ActionListener, MouseAdapter
from java.lang import Runnable, Thread as JThread, String as JString
from java.io import File
import json
import re
import os
import time
import threading
import sys
import traceback

class SwingRunner(Runnable):
    def __init__(self, func, *args, **kwargs):
        self._func = func
        self._args = args
        self._kwargs = kwargs
    def run(self):
        try:
            self._func(*self._args, **self._kwargs)
        except:
            print("Layout/UI Error in SwingRunner:")
            traceback.print_exc()

def invokeLater(func, *args, **kwargs):
    SwingUtilities.invokeLater(SwingRunner(func, *args, **kwargs))

# =============================================================================
# CONSTANTS
# =============================================================================

EXTENSION_NAME = "FlipFlow"
STORAGE_DIR = os.path.join(os.path.expanduser("~"), ".flipflow")
VAR_PATTERN = re.compile(r"\{\{\s*([\w\.-]+)\s*\}\}")

AUTO_DETECT_TOKENS = [
    "csrf", "xsrf", "_token", "csrf_token", "xsrf_token",
    "jwt", "bearer", "access_token", "refresh_token",
    "auth_token", "sessionid", "session_id", "sid",
    "api_key", "apikey", "nonce"
]

# Colors for UI
COLOR_BG = Color(43, 43, 43)
COLOR_BG_LIGHT = Color(60, 63, 65)
COLOR_BG_PANEL = Color(49, 51, 53)
COLOR_FG = Color(187, 187, 187)
COLOR_FG_DIM = Color(130, 130, 130)
COLOR_ACCENT = Color(75, 110, 175)
COLOR_SUCCESS = Color(80, 160, 80)
COLOR_ERROR = Color(200, 80, 80)
COLOR_WARNING = Color(200, 170, 60)
COLOR_BORDER = Color(70, 70, 70)

FONT_MONO = Font("Monospaced", Font.PLAIN, 12)
FONT_UI = Font("SansSerif", Font.PLAIN, 12)
FONT_UI_BOLD = Font("SansSerif", Font.BOLD, 12)
FONT_HEADER = Font("SansSerif", Font.BOLD, 14)

# =============================================================================
# DATA MODELS
# =============================================================================

class ExtractionRule(object):
    """Defines how to extract a variable from an HTTP response."""

    def __init__(self, var_name="", method="regex", pattern="", source="response_body"):
        self.var_name = var_name
        self.method = method          # regex | jsonpath | header | cookie
        self.pattern = pattern
        self.source = source          # response_body | response_headers

    def to_dict(self):
        return {
            "var_name": self.var_name,
            "method": self.method,
            "pattern": self.pattern,
            "source": self.source
        }

    @staticmethod
    def from_dict(d):
        return ExtractionRule(
            var_name=d.get("var_name", ""),
            method=d.get("method", "regex"),
            pattern=d.get("pattern", ""),
            source=d.get("source", "response_body")
        )


class ConditionalAction(object):
    """Post-step action triggered on specific response status."""

    def __init__(self, status_code=401, target_workflow=""):
        self.status_code = status_code
        self.target_workflow = target_workflow

    def to_dict(self):
        return {
            "status_code": self.status_code,
            "target_workflow": self.target_workflow
        }

    @staticmethod
    def from_dict(d):
        return ConditionalAction(
            status_code=d.get("status_code", 401),
            target_workflow=d.get("target_workflow", "")
        )


class StepModel(object):
    """One HTTP request step in a workflow."""

    def __init__(self, name="", host="", port=443, use_https=True,
                 raw_request="", extraction_rules=None, conditional=None, enabled=True):
        self.name = name
        self.host = host
        self.port = port
        self.use_https = use_https
        self.raw_request = raw_request
        self.extraction_rules = extraction_rules or []
        self.conditional = conditional
        self.enabled = enabled

    def to_dict(self):
        d = {
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "use_https": self.use_https,
            "raw_request": self.raw_request,
            "extraction_rules": [r.to_dict() for r in self.extraction_rules],
            "enabled": self.enabled
        }
        if self.conditional:
            d["conditional"] = self.conditional.to_dict()
        return d

    @staticmethod
    def from_dict(d):
        conditional = None
        if "conditional" in d:
            conditional = ConditionalAction.from_dict(d["conditional"])
        return StepModel(
            name=d.get("name", ""),
            host=d.get("host", ""),
            port=d.get("port", 443),
            use_https=d.get("use_https", True),
            raw_request=d.get("raw_request", ""),
            extraction_rules=[ExtractionRule.from_dict(r) for r in d.get("extraction_rules", [])],
            conditional=conditional,
            enabled=d.get("enabled", True)
        )


class WorkflowModel(object):
    """A named workflow containing ordered steps."""

    def __init__(self, name="New Workflow", steps=None, description=""):
        self.name = name
        self.steps = steps or []
        self.description = description

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "steps": [s.to_dict() for s in self.steps]
        }

    @staticmethod
    def from_dict(d):
        return WorkflowModel(
            name=d.get("name", "New Workflow"),
            steps=[StepModel.from_dict(s) for s in d.get("steps", [])],
            description=d.get("description", "")
        )


# =============================================================================
# VARIABLE STORE
# =============================================================================

class VariableStore(object):
    """Thread-safe variable storage with substitution support."""

    def __init__(self):
        self._vars = {}
        self._lock = threading.Lock()
        self._listeners = []

    def set(self, name, value):
        normalized = name.lower().strip()
        with self._lock:
            self._vars[normalized] = value
        print("[VariableStore] SET %s = %s" % (normalized, str(value)[:100]))
        self._notify()

    def get(self, name, default=""):
        with self._lock:
            return self._vars.get(name.lower().strip(), default)

    def get_all(self):
        with self._lock:
            return dict(self._vars)

    def remove(self, name):
        with self._lock:
            self._vars.pop(name.lower().strip(), None)
        self._notify()

    def clear(self):
        with self._lock:
            self._vars.clear()
        self._notify()

    def substitute(self, text):
        """Replace all {{var_name}} occurrences with stored values."""
        if not text:
            return text

        def replacer(match):
            var_name = match.group(1).lower().strip()
            with self._lock:
                val = self._vars.get(var_name)
                if val is not None:
                    print("[VariableStore] SUB %s -> %s" % (var_name, str(val)[:50]))
                    return str(val)
                print("[VariableStore] SUB FAILED: %s not found" % var_name)
                return match.group(0) # Keep as {{var}} if not found

        return VAR_PATTERN.sub(replacer, text)

    def add_listener(self, callback):
        self._listeners.append(callback)

    def _notify(self):
        for cb in self._listeners:
            try:
                cb()
            except Exception:
                pass


# =============================================================================
# EXTRACTION ENGINE
# =============================================================================

class ExtractionEngine(object):
    """Extracts variable values from HTTP responses."""

    @staticmethod
    def extract(rule, response_bytes, helpers, var_store=None):
        """Extract a value using the given rule. Returns (value, error)."""
        try:
            if response_bytes is None:
                return None, "No response"

            # Automatically uncompress if needed (e.g. gzip)
            if hasattr(helpers, "uncompressResponse"):
                response_bytes = helpers.uncompressResponse(response_bytes)

            # Substitute variables in pattern if store provided
            pattern = rule.pattern
            if var_store:
                pattern = var_store.substitute(pattern)

            response_str = helpers.bytesToString(response_bytes)
            response_info = helpers.analyzeResponse(response_bytes)
            headers = response_info.getHeaders()
            body_offset = response_info.getBodyOffset()
            body = response_str[body_offset:]

            if rule.method == "regex":
                return ExtractionEngine._extract_regex(pattern, rule.source, body, response_str)
            elif rule.method == "jsonpath":
                return ExtractionEngine._extract_jsonpath(pattern, body)
            elif rule.method == "header":
                return ExtractionEngine._extract_header(pattern, headers)
            elif rule.method == "cookie":
                return ExtractionEngine._extract_cookie(pattern, headers)
            else:
                return None, "Unknown method: %s" % rule.method
        except Exception as e:
            print("[ExtractionEngine] GLOBAL ERROR: %s" % str(e))
            traceback.print_exc()
            return None, str(e)

    @staticmethod
    def _extract_regex(pattern, source_type, body, full_response):
        source = body if source_type == "response_body" else full_response
        match = re.search(pattern, source)
        if match:
            return match.group(1) if match.lastindex else match.group(0), None
        return None, "No regex match for: %s" % pattern

    @staticmethod
    def _extract_jsonpath(pattern, body):
        """Lightweight JSONPath: supports dot and bracket notation."""
        try:
            data = json.loads(body)
        except ValueError:
            return None, "Response body is not valid JSON"

        path = pattern.strip()
        if path.startswith("$"):
            path = path[1:]
        
        # Tokenize: matches .key, key, ['key'], [0]
        # Groups: 1=dot/plain key, 2=bracket key/index
        tokens = re.findall(r'\.?([\w-]+)|\[["\']?([^"\'\]]+)["\']?\]', path)
        parts = []
        for t in tokens:
            if t[0]: # key
                parts.append(t[0])
            elif t[1]: # bracket
                val = t[1]
                parts.append(int(val) if val.isdigit() else val)

        current = data
        for part in parts:
            try:
                if isinstance(part, int):
                    current = current[part]
                elif isinstance(current, dict):
                    current = current[part]
                elif isinstance(current, list) and str(part).isdigit():
                    current = current[int(part)]
                else:
                    return None, "Path not found: %s" % pattern
            except (KeyError, IndexError, TypeError, ValueError):
                return None, "Path not found: %s" % pattern

        if current is None:
            return "null", None
        if isinstance(current, (dict, list)):
            return json.dumps(current), None
        return str(current), None

    @staticmethod
    def _extract_header(pattern, headers):
        target = pattern.lower().strip()
        for header in headers:
            if ":" in header:
                name, value = header.split(":", 1)
                if name.strip().lower() == target:
                    return value.strip(), None
        return None, "Header not found: %s" % pattern

    @staticmethod
    def _extract_cookie(pattern, headers):
        target = pattern.strip()
        for header in headers:
            if header.lower().startswith("set-cookie:"):
                cookie_str = header.split(":", 1)[1].strip()
                parts = cookie_str.split(";")
                if parts:
                    name_val = parts[0].strip()
                    if "=" in name_val:
                        name, val = name_val.split("=", 1)
                        if name.strip() == target:
                            return val.strip(), None
        return None, "Cookie not found: %s" % pattern


# =============================================================================
# AUTO TOKEN DETECTOR
# =============================================================================

class AutoTokenDetector(object):
    """Scans responses for common security tokens."""

    @staticmethod
    def detect(response_str):
        """Returns list of (token_name, suggested_var, suggested_regex)."""
        found = []
        lower = response_str.lower()
        for token in AUTO_DETECT_TOKENS:
            if token in lower:
                patterns = [
                    r'"%s"\s*:\s*"([^"]+)"' % token,
                    r"'%s'\s*:\s*'([^']+)'" % token,
                    r'%s=([^&;\s"<>]+)' % token,
                    r'name="%s"[^>]*value="([^"]*)"' % token,
                ]
                for pat in patterns:
                    match = re.search(pat, response_str, re.IGNORECASE)
                    if match:
                        found.append((token, token, pat))
                        break
        return found


# =============================================================================
# EXECUTION ENGINE
# =============================================================================

class StepResult(object):
    """Result of executing one step."""

    def __init__(self, step_index, step_name):
        self.step_index = step_index
        self.step_name = step_name
        self.request_sent = ""
        self.response_status = 0
        self.response_body_preview = ""
        self.extracted = {}        # {var_name: value}
        self.errors = []
        self.token_suggestions = []
        self.exec_time_ms = 0
        self.skipped = False
        self.req_resp = None # IHttpRequestResponse

    def __str__(self):
        if self.skipped:
            return "[Step %d] %s — SKIPPED (disabled)" % (self.step_index + 1, self.step_name)
        lines = []
        lines.append("[Step %d] %s" % (self.step_index + 1, self.step_name))
        lines.append("  Status: %d | Time: %dms" % (self.response_status, self.exec_time_ms))
        for var, val in self.extracted.items():
            display_val = val[:80] + "..." if len(val) > 80 else val
            lines.append("  Extracted %s = %s" % (var, display_val))
        for err in self.errors:
            lines.append("  ERROR: %s" % err)
        for token, var, pat in self.token_suggestions:
            lines.append("  [!] Token detected: %s" % token)
        return "\n".join(lines)


class ExecutionEngine(object):
    """Runs workflow steps sequentially."""

    def __init__(self, callbacks, helpers, variable_store, workflow_manager=None):
        self._callbacks = callbacks
        self._helpers = helpers
        self._var_store = variable_store
        self._workflow_manager = workflow_manager

    def execute_workflow(self, workflow, log_callback=None):
        """Execute all steps. Returns list of StepResult."""
        print("Starting workflow execution: %s" % workflow.name)
        results = []
        for i, step in enumerate(workflow.steps):
            print("  Executing step %d: %s" % (i + 1, step.name))
            result = self._execute_step(i, step)
            results.append(result)
            if log_callback:
                log_callback(result)
            print("  Step %d finished with status %d" % (i + 1, result.response_status))

            # Conditional action
            if step.conditional and not result.skipped:
                if result.response_status == step.conditional.status_code:
                    if step.conditional.target_workflow and self._workflow_manager:
                        target_name = self._var_store.substitute(step.conditional.target_workflow)
                        target = self._workflow_manager.get_workflow(target_name)
                        if target:
                            sub_results = self.execute_workflow(target, log_callback)
                            results.extend(sub_results)

        return results

    def _prepare_request(self, raw):
        """Normalize line endings to CRLF and update Content-Length if body changed."""
        # 1. Normalize line endings to CRLF
        normalized = raw.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
        
        # 2. Split into headers and body
        parts = normalized.split("\r\n\r\n", 1)
        if len(parts) < 2:
            return normalized # No body found, return normalized headers
            
        header_lines = parts[0].split("\r\n")
        body = parts[1]
        
        # 3. Recalculate Content-Length
        body_len = len(body)
        new_headers = []
        found_cl = False
        is_chunked = False
        
        for line in header_lines:
            low = line.lower()
            if low.startswith("content-length:"):
                found_cl = True
                continue # Skip for now, we'll re-add if not chunked
            if low.startswith("transfer-encoding:") and "chunked" in low:
                is_chunked = True
            new_headers.append(line)
        
        # Add Content-Length if body exists and not chunked
        if not is_chunked and (found_cl or body_len > 0):
            new_headers.append("Content-Length: %d" % body_len)
            
        return "\r\n".join(new_headers) + "\r\n\r\n" + body

    def _execute_step(self, index, step):
        """Execute a single step."""
        result = StepResult(index, step.name or ("Step %d" % (index + 1)))

        if not step.enabled:
            result.skipped = True
            return result

        try:
            # Substitute variables in request
            raw = self._var_store.substitute(step.raw_request)
            host = self._var_store.substitute(step.host)
            
            # Normalize and update Content-Length
            raw = self._prepare_request(raw)
            result.request_sent = raw

            # Build request bytes
            request_bytes = self._helpers.stringToBytes(raw)

            # Create HTTP service
            service = self._helpers.buildHttpService(host, step.port, step.use_https)

            # Send request
            start = time.time()
            req_resp = self._callbacks.makeHttpRequest(service, request_bytes)
            elapsed = int((time.time() - start) * 1000)
            result.exec_time_ms = elapsed
            result.req_resp = req_resp

            response_bytes = req_resp.getResponse()
            if response_bytes is None:
                result.errors.append("No response received")
                return result

            # Parse response status
            response_info = self._helpers.analyzeResponse(response_bytes)
            result.response_status = response_info.getStatusCode()

            response_str = self._helpers.bytesToString(response_bytes)
            body_offset = response_info.getBodyOffset()
            result.response_body_preview = response_str[body_offset:body_offset + 500]

            # Extract variables
            for rule in step.extraction_rules:
                value, error = ExtractionEngine.extract(rule, response_bytes, self._helpers, self._var_store)
                if value is not None:
                    self._var_store.set(rule.var_name, value)
                    result.extracted[rule.var_name] = value
                elif error:
                    result.errors.append("%s: %s" % (rule.var_name, error))

            # Auto detect tokens
            detections = AutoTokenDetector.detect(response_str)
            result.token_suggestions = detections

        except Exception as e:
            result.errors.append("Execution error: %s" % str(e))

        return result


# =============================================================================
# WORKFLOW MANAGER (Persistence)
# =============================================================================

class WorkflowManager(object):
    """CRUD operations and JSON persistence for workflows."""

    def __init__(self):
        self._workflows = []
        self._listeners = []
        self._ensure_storage_dir()
        self.load_all()

    def _ensure_storage_dir(self):
        if not os.path.exists(STORAGE_DIR):
            os.makedirs(STORAGE_DIR)

    def load_all(self):
        self._workflows = []
        if not os.path.exists(STORAGE_DIR):
            return
        for fname in os.listdir(STORAGE_DIR):
            if fname.endswith(".json"):
                path = os.path.join(STORAGE_DIR, fname)
                try:
                    with open(path, "r") as f:
                        data = json.load(f)
                    wf = WorkflowModel.from_dict(data)
                    self._workflows.append(wf)
                except Exception:
                    pass
        self._notify()

    def save_workflow(self, workflow):
        self._ensure_storage_dir()
        safe_name = re.sub(r'[^\w\-]', '_', workflow.name)
        path = os.path.join(STORAGE_DIR, safe_name + ".json")
        with open(path, "w") as f:
            json.dump(workflow.to_dict(), f, indent=2)

    def save_all(self):
        for wf in self._workflows:
            self.save_workflow(wf)

    def get_workflows(self):
        return list(self._workflows)

    def get_workflow(self, name):
        for wf in self._workflows:
            if wf.name == name:
                return wf
        return None

    def create_workflow(self, name="New Workflow"):
        counter = 1
        base_name = name
        while self.get_workflow(name):
            name = "%s (%d)" % (base_name, counter)
            counter += 1
        wf = WorkflowModel(name=name)
        self._workflows.append(wf)
        self.save_workflow(wf)
        self._notify()
        return wf

    def delete_workflow(self, workflow):
        if workflow in self._workflows:
            self._workflows.remove(workflow)
            safe_name = re.sub(r'[^\w\-]', '_', workflow.name)
            path = os.path.join(STORAGE_DIR, safe_name + ".json")
            if os.path.exists(path):
                os.remove(path)
            self._notify()

    def rename_workflow(self, workflow, new_name):
        old_safe = re.sub(r'[^\w\-]', '_', workflow.name)
        old_path = os.path.join(STORAGE_DIR, old_safe + ".json")
        if os.path.exists(old_path):
            os.remove(old_path)
        workflow.name = new_name
        self.save_workflow(workflow)
        self._notify()

    def duplicate_workflow(self, workflow):
        data = workflow.to_dict()
        data["name"] = workflow.name + " (Copy)"
        new_wf = WorkflowModel.from_dict(data)
        counter = 1
        base = new_wf.name
        while self.get_workflow(new_wf.name):
            new_wf.name = "%s %d" % (base, counter)
            counter += 1
        self._workflows.append(new_wf)
        self.save_workflow(new_wf)
        self._notify()
        return new_wf

    def add_listener(self, callback):
        self._listeners.append(callback)

    def _notify(self):
        for cb in self._listeners:
            try:
                cb()
            except Exception:
                pass


# =============================================================================
# UI COMPONENTS - LISTS & TABLES
# =============================================================================

class VariablesTableModel(AbstractTableModel):
    def __init__(self, var_store):
        self._var_store = var_store
        self._keys = sorted(var_store.get_all().keys())
        self._var_store.add_listener(self.refresh)

    def refresh(self):
        self._keys = sorted(self._var_store.get_all().keys())
        self.fireTableDataChanged()

    def getRowCount(self):
        return len(self._keys)

    def getColumnCount(self):
        return 2

    def getColumnName(self, col):
        return ["Variable", "Value"][col]

    def getValueAt(self, row, col):
        if row >= len(self._keys): return ""
        key = self._keys[row]
        if col == 0: return key
        return self._var_store.get(key)

    def isCellEditable(self, row, col):
        return col == 1

    def setValueAt(self, value, row, col):
        if col == 1:
            self._var_store.set(self._keys[row], value)


class SelectionListenerWrapper(ListSelectionListener):
    def __init__(self, callback): self.callback = callback
    def valueChanged(self, e): self.callback(e)


class FlowListPanel(JPanel):
    def __init__(self, manager, on_select_callback):
        self.setLayout(BorderLayout())
        self._manager = manager
        self._on_select = on_select_callback
        self._list_model = DefaultListModel()

        self._list = JList(self._list_model)
        self._list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._selection_listener = SelectionListenerWrapper(self._list_selected)
        self._list.addListSelectionListener(self._selection_listener)

        scroll = JScrollPane(self._list)
        scroll.setBorder(BorderFactory.createTitledBorder("Workflows"))
        self.add(scroll, BorderLayout.CENTER)

        # Buttons
        btn_panel = JPanel(GridLayout(3, 2, 2, 2))
        btn_panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))

        btn_new = JButton("+ New", actionPerformed=self._new_flow)
        btn_dup = JButton("Duplicate", actionPerformed=self._dup_flow)
        btn_del = JButton("Delete", actionPerformed=self._del_flow)
        btn_ren = JButton("Rename", actionPerformed=self._ren_flow)
        btn_imp = JButton("Import", actionPerformed=self._import_workflow)
        btn_exp = JButton("Export", actionPerformed=self._export_workflow)

        btn_panel.add(btn_new)
        btn_panel.add(btn_dup)
        btn_panel.add(btn_ren)
        btn_panel.add(btn_del)
        btn_panel.add(btn_imp)
        btn_panel.add(btn_exp)

        self.add(btn_panel, BorderLayout.SOUTH)
        self.refresh()

    def refresh(self):
        self._list.removeListSelectionListener(self._selection_listener)
        try:
            selected = self._list.getSelectedValue()
            self._list_model.clear()
            for wf in self._manager.get_workflows():
                self._list_model.addElement(wf.name)
            if selected:
                self._list.setSelectedValue(selected, True)
        finally:
            self._list.addListSelectionListener(self._selection_listener)

    def _list_selected(self, event):
        if not event.getValueIsAdjusting():
            name = self._list.getSelectedValue()
            if name:
                wf = self._manager.get_workflow(name)
                self._on_select(wf)

    def _new_flow(self, event):
        name = JOptionPane.showInputDialog(self, "Workflow Name:")
        if name:
            wf = self._manager.create_workflow(name)
            self.refresh()
            self._list.setSelectedValue(wf.name, True)

    def _dup_flow(self, event):
        name = self._list.getSelectedValue()
        if name:
            wf = self._manager.get_workflow(name)
            new_wf = self._manager.duplicate_workflow(wf)
            self.refresh()
            self._list.setSelectedValue(new_wf.name, True)

    def _del_flow(self, event):
        name = self._list.getSelectedValue()
        if name:
            res = JOptionPane.showConfirmDialog(self, "Delete workflow '%s'?" % name)
            if res == JOptionPane.YES_OPTION:
                wf = self._manager.get_workflow(name)
                self._manager.delete_workflow(wf)
                self.refresh()

    def _import_workflow(self, event):
        try:
            chooser = JFileChooser()
            chooser.setDialogTitle("Import Workflow")
            chooser.setFileFilter(FileNameExtensionFilter("JSON Files (*.json)", ["json"]))
            res = chooser.showOpenDialog(self)
            if res == JFileChooser.APPROVE_OPTION:
                f = chooser.getSelectedFile()
                try:
                    with open(f.getAbsolutePath(), 'r') as fp:
                        data = json.load(fp)
                    new_wf = WorkflowModel.from_dict(data)
                    
                    # Check if it already exists by name
                    base_name = new_wf.name
                    counter = 1
                    while self._manager.get_workflow(new_wf.name):
                        new_wf.name = "%s (Imported %d)" % (base_name, counter)
                        counter += 1
                    
                    self._manager._workflows.append(new_wf)
                    self._manager.save_workflow(new_wf)
                    self.refresh()
                    self._list.setSelectedValue(new_wf.name, True)
                    JOptionPane.showMessageDialog(self, "Workflow '%s' imported successfully." % new_wf.name)
                except Exception as e:
                    JOptionPane.showMessageDialog(self, "Error importing workflow: %s" % str(e))
                    traceback.print_exc()
        except Exception as e:
            print("[FlipFlow] Import Error: %s" % str(e))
            traceback.print_exc()

    def _export_workflow(self, event):
        try:
            name = self._list.getSelectedValue()
            if not name:
                JOptionPane.showMessageDialog(self, "Select a workflow to export.")
                return
                
            wf = self._manager.get_workflow(name)
            chooser = JFileChooser()
            chooser.setDialogTitle("Export Workflow")
            
            # Suggest a filename
            safe_name = re.sub(r'[^\w\-]', '_', wf.name)
            home_dir = os.path.expanduser("~")
            suggested_file = File(os.path.join(home_dir, "%s.json" % safe_name))
            chooser.setSelectedFile(suggested_file)
            chooser.setFileFilter(FileNameExtensionFilter("JSON Files (*.json)", ["json"]))
            
            res = chooser.showSaveDialog(self)
            if res == JFileChooser.APPROVE_OPTION:
                f = chooser.getSelectedFile()
                path = f.getAbsolutePath()
                if not path.lower().endswith(".json"):
                    path += ".json"
                
                try:
                    # Check for overwrite if not selected via dialog's own check (some platforms differ)
                    if os.path.exists(path):
                        confirm = JOptionPane.showConfirmDialog(self, "File exists. Overwrite?", "Confirm Save", JOptionPane.YES_NO_OPTION)
                        if confirm != JOptionPane.YES_OPTION:
                            return

                    with open(path, 'w') as fp:
                        json.dump(wf.to_dict(), fp, indent=4)
                    JOptionPane.showMessageDialog(self, "Workflow exported successfully to:\n%s" % path)
                except Exception as e:
                    JOptionPane.showMessageDialog(self, "Error exporting workflow: %s" % str(e))
                    traceback.print_exc()
        except Exception as e:
            print("[FlipFlow] Export Error: %s" % str(e))
            traceback.print_exc()

    def _ren_flow(self, event):
        name = self._list.getSelectedValue()
        if name:
            new_name = JOptionPane.showInputDialog(self, "New Name:", name)
            if new_name and new_name != name:
                wf = self._manager.get_workflow(name)
                self._manager.rename_workflow(wf, new_name)
                self.refresh()
                self._list.setSelectedValue(new_name, True)



# =============================================================================
# STEP EDITOR COMPONENTS
# =============================================================================

from javax.swing.event import DocumentListener

class FieldChangeListener(DocumentListener):
    def __init__(self, callback): self.callback = callback
    def insertUpdate(self, e): self.callback()
    def removeUpdate(self, e): self.callback()
    def changedUpdate(self, e): self.callback()

class StepCard(JPanel):
    """UI card for a single step in the workflow."""
    def __init__(self, step, index, on_change, on_action):
        self.setLayout(BorderLayout())
        self.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(COLOR_BORDER),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ))

        self.step = step
        self.index = index
        self.on_change = on_change
        self.on_action = on_action # (action_name, index)

        header = JPanel(BorderLayout())
        header.setOpaque(False)

        title_panel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 0))
        title_panel.setOpaque(False)

        self._enabled_chk = JCheckBox("", step.enabled, actionPerformed=self._field_changed)
        self._enabled_chk.setOpaque(False)

        title_label = JLabel("Step %d:" % (index + 1))
        title_label.setFont(FONT_UI_BOLD)

        self._name_field = JTextField(step.name, 15)
        self._name_field.getDocument().addDocumentListener(FieldChangeListener(self._field_changed))

        title_panel.add(self._enabled_chk)
        title_panel.add(title_label)
        title_panel.add(self._name_field)
        header.add(title_panel, BorderLayout.WEST)

        # Action buttons
        btn_panel = JPanel(FlowLayout(FlowLayout.RIGHT, 2, 0))
        btn_panel.setOpaque(False)
        for act in ["Up", "Down", "Dup", "Del"]:
            btn = JButton(act)
            btn.setMargin(Insets(2, 4, 2, 4))
            btn.addActionListener(lambda e, a=act: self.on_action(a, self.index))
            btn_panel.add(btn)
        header.add(btn_panel, BorderLayout.EAST)

        self.add(header, BorderLayout.NORTH)

        # Config row
        config_panel = JPanel(FlowLayout(FlowLayout.LEFT, 10, 5))
        config_panel.setOpaque(False)

        config_panel.add(JLabel("Host:"))
        self._host_field = JTextField(step.host, 15)
        self._host_field.getDocument().addDocumentListener(FieldChangeListener(self._field_changed))
        config_panel.add(self._host_field)

        config_panel.add(JLabel("Port:"))
        self._port_field = JTextField(str(step.port), 5)
        self._port_field.getDocument().addDocumentListener(FieldChangeListener(self._field_changed))
        config_panel.add(self._port_field)

        self._https_chk = JCheckBox("HTTPS", step.use_https, actionPerformed=self._field_changed)
        self._https_chk.setOpaque(False)
        config_panel.add(self._https_chk)
        
        self._cond_btn = JButton("Post-Action", actionPerformed=self._edit_cond)
        config_panel.add(self._cond_btn)

        # Main Body
        body_panel = JPanel(GridLayout(1, 2, 10, 0))
        body_panel.setOpaque(False)

        # Request Editor
        req_panel = JPanel(BorderLayout())
        req_panel.setOpaque(False)
        req_panel.add(JLabel("Request:"), BorderLayout.NORTH)
        self._req_area = JTextArea(step.raw_request, 8, 30)
        self._req_area.setFont(FONT_MONO)
        self._req_area.getDocument().addDocumentListener(FieldChangeListener(self._field_changed))
        req_panel.add(JScrollPane(self._req_area), BorderLayout.CENTER)
        body_panel.add(req_panel)

        # Extraction Rules Panel
        ext_panel = JPanel(BorderLayout())
        ext_panel.setOpaque(False)
        ext_label_panel = JPanel(BorderLayout())
        ext_label_panel.setOpaque(False)
        ext_label_panel.add(JLabel("Extraction Rules:"), BorderLayout.WEST)
        btn_add_ext = JButton("+", actionPerformed=self._add_rule)
        btn_add_ext.setMargin(Insets(0, 2, 0, 2))
        btn_rem_ext = JButton("-", actionPerformed=self._remove_rule)
        btn_rem_ext.setMargin(Insets(0, 2, 0, 2))
        
        button_panel = JPanel(FlowLayout(FlowLayout.RIGHT, 2, 0))
        button_panel.setOpaque(False)
        button_panel.add(btn_add_ext)
        button_panel.add(btn_rem_ext)
        ext_label_panel.add(button_panel, BorderLayout.EAST)
        ext_panel.add(ext_label_panel, BorderLayout.NORTH)

        self._rules_list_model = DefaultListModel()
        self._update_rules_list()
        self._rules_list = JList(self._rules_list_model)
        self._rules_list.setFont(Font("SansSerif", Font.PLAIN, 11))
        self._rules_list.addMouseListener(RuleMouseListener(self))
        ext_panel.add(JScrollPane(self._rules_list), BorderLayout.CENTER)
        body_panel.add(ext_panel)

        center_container = JPanel(BorderLayout())
        center_container.setOpaque(False)
        center_container.add(config_panel, BorderLayout.NORTH)
        center_container.add(body_panel, BorderLayout.CENTER)
        self.add(center_container, BorderLayout.CENTER)

    def _field_changed(self, event=None):
        self.step.enabled = self._enabled_chk.isSelected()
        self.step.name = self._name_field.getText()
        self.step.host = self._host_field.getText()
        try:
            val = self._port_field.getText()
            if val: self.step.port = int(val)
        except ValueError: pass
        self.step.use_https = self._https_chk.isSelected()
        self.step.raw_request = self._req_area.getText()
        self.on_change()

    def _update_rules_list(self):
        self._rules_list_model.clear()
        for r in self.step.extraction_rules:
            self._rules_list_model.addElement("%s (%s)" % (r.var_name, r.method))

    def _add_rule(self, event):
        rule = ExtractionRule(var_name="new_var", method="regex", pattern=".*")
        if self._edit_rule_dialog(rule):
            self.step.extraction_rules.append(rule)
            self._update_rules_list()
            self._field_changed()

    def _remove_rule(self, event=None):
        idx = self._rules_list.getSelectedIndex()
        if idx >= 0:
            self.step.extraction_rules.pop(idx)
            self._update_rules_list()
            self._field_changed()

    def edit_rule_at(self, index):
        rule = self.step.extraction_rules[index]
        if self._edit_rule_dialog(rule):
            self._update_rules_list()
            self._field_changed()

    def _edit_rule_dialog(self, rule):
        panel = JPanel(GridLayout(0, 2, 5, 5))
        panel.add(JLabel("Variable Name:"))
        name_f = JTextField(rule.var_name)
        panel.add(name_f)
        panel.add(JLabel("Method:"))
        method_c = JComboBox(["regex", "jsonpath", "header", "cookie"])
        method_c.setSelectedItem(rule.method)
        panel.add(method_c)
        panel.add(JLabel("Pattern:"))
        pat_f = JTextField(rule.pattern)
        panel.add(pat_f)
        panel.add(JLabel("Source:"))
        src_c = JComboBox(["response_body", "response_headers"])
        src_c.setSelectedItem(rule.source)
        panel.add(src_c)
        res = JOptionPane.showConfirmDialog(None, panel, "Edit Extraction Rule", JOptionPane.OK_CANCEL_OPTION)
        if res == JOptionPane.OK_OPTION:
            rule.var_name = name_f.getText()
            rule.method = method_c.getSelectedItem()
            rule.pattern = pat_f.getText()
            rule.source = src_c.getSelectedItem()
            return True
        return False

    def _edit_cond(self, event):
        if not self.step.conditional:
            self.step.conditional = ConditionalAction()
        panel = JPanel(GridLayout(0, 2, 5, 5))
        panel.add(JLabel("On Status Code:"))
        status_f = JTextField(str(self.step.conditional.status_code))
        panel.add(status_f)
        panel.add(JLabel("Run Workflow:"))
        wf_f = JTextField(self.step.conditional.target_workflow)
        panel.add(wf_f)
        res = JOptionPane.showConfirmDialog(None, panel, "Conditional Post-Action", JOptionPane.OK_CANCEL_OPTION)
        if res == JOptionPane.OK_OPTION:
            try:
                self.step.conditional.status_code = int(status_f.getText())
                self.step.conditional.target_workflow = wf_f.getText()
                self._field_changed()
            except ValueError: pass

class RuleMouseListener(MouseAdapter):
    def __init__(self, card): self.card = card
    def mouseClicked(self, e):
        if e.getClickCount() == 2:
            idx = self.card._rules_list.getSelectedIndex()
            if idx >= 0: self.card.edit_rule_at(idx)
        elif SwingUtilities.isRightMouseButton(e):
            idx = self.card._rules_list.locationToIndex(e.getPoint())
            if idx >= 0:
                self.card._rules_list.setSelectedIndex(idx)
                menu = JPopupMenu()
                item_del = JMenuItem("Remove", actionPerformed=lambda x: self.card._remove_rule())
                menu.add(item_del)
                menu.show(e.getComponent(), e.getX(), e.getY())


class StepEditorPanel(JPanel):
    def __init__(self, on_change):
        self.setLayout(BorderLayout())
        self._on_change = on_change
        self._workflow = None
        
        self._container = JPanel()
        self._container.setLayout(BoxLayout(self._container, BoxLayout.Y_AXIS))
        
        scroll = JScrollPane(self._container)
        scroll.getVerticalScrollBar().setUnitIncrement(16)
        self.add(scroll, BorderLayout.CENTER)
        
        bottom_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        btn_add = JButton("Add Step", actionPerformed=self._add_step)
        bottom_panel.add(btn_add)
        self.add(bottom_panel, BorderLayout.SOUTH)

    def load_workflow(self, workflow):
        self._workflow = workflow
        self.refresh()

    def refresh(self):
        self._container.removeAll()
        if not self._workflow:
            self._container.add(JLabel("Select a workflow from the list"))
        else:
            for i, step in enumerate(self._workflow.steps):
                card = StepCard(step, i, self._on_step_change, self._on_step_action)
                self._container.add(card)
                self._container.add(Box.createRigidArea(Dimension(0, 10)))
        
        self._container.revalidate()
        self._container.repaint()

    def _on_step_change(self):
        if self._workflow:
            self._on_change(self._workflow)

    def _on_step_action(self, action, index):
        if not self._workflow: return
        
        if action == "Del":
            self._workflow.steps.pop(index)
        elif action == "Dup":
            old = self._workflow.steps[index]
            new_step = StepModel.from_dict(old.to_dict())
            self._workflow.steps.insert(index + 1, new_step)
        elif action == "Up" and index > 0:
            self._workflow.steps[index], self._workflow.steps[index-1] = \
                self._workflow.steps[index-1], self._workflow.steps[index]
        elif action == "Down" and index < len(self._workflow.steps) - 1:
            self._workflow.steps[index], self._workflow.steps[index+1] = \
                self._workflow.steps[index+1], self._workflow.steps[index]
        
        self.refresh()
        self._on_step_change()

    def _add_step(self, event):
        if self._workflow:
            new_step = StepModel(name="New Step", host="example.com", port=443, use_https=True, raw_request="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            self._workflow.steps.append(new_step)
            self.refresh()
            self._on_step_change()

    def add_step_from_request(self, host, port, https, request_str):
        if not self._workflow: return
        new_step = StepModel(name="Imported Step", host=host, port=port, use_https=https, raw_request=request_str)
        self._workflow.steps.append(new_step)
        self.refresh()
        self._on_step_change()


class ResponseInspectorPanel(JPanel, IMessageEditorController):
    def __init__(self, callbacks):
        self.setLayout(BorderLayout())
        self._callbacks = callbacks
        self._request_viewer = callbacks.createMessageEditor(self, False)
        self._response_viewer = callbacks.createMessageEditor(self, False)
        
        self._current_message = None
        self._results = []
        
        top_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        top_panel.add(JLabel("Select Step:"))
        self._step_combo = JComboBox()
        self._step_combo.addActionListener(self._step_selected)
        top_panel.add(self._step_combo)
        self.add(top_panel, BorderLayout.NORTH)
        
        tabs = JTabbedPane()
        tabs.addTab("Request", self._request_viewer.getComponent())
        tabs.addTab("Response", self._response_viewer.getComponent())
        self.add(tabs, BorderLayout.CENTER)

    def add_result(self, result):
        if result.req_resp:
            self._results.append(result)
            def update():
                self._step_combo.addItem("%d: %s" % (result.step_index + 1, result.step_name))
                if self._step_combo.getItemCount() == 1:
                    self._step_combo.setSelectedIndex(0)
            invokeLater(update)

    def clear(self):
        self._results = []
        self._current_message = None
        def update():
            self._step_combo.removeAllItems()
            self._request_viewer.setMessage(None, True)
            self._response_viewer.setMessage(None, False)
        invokeLater(update)

    def _step_selected(self, event):
        idx = self._step_combo.getSelectedIndex()
        if idx >= 0 and idx < len(self._results):
            self._current_message = self._results[idx].req_resp
            if self._current_message:
                self._request_viewer.setMessage(self._current_message.getRequest(), True)
                self._response_viewer.setMessage(self._current_message.getResponse(), False)
            else:
                self._request_viewer.setMessage(None, True)
                self._response_viewer.setMessage(None, False)

    # IMessageEditorController
    def getHttpService(self):
        msg = self._current_message
        return msg.getHttpService() if msg else None
    def getRequest(self):
        msg = self._current_message
        return msg.getRequest() if msg else None
    def getResponse(self):
        msg = self._current_message
        return msg.getResponse() if msg else None


class ExecutionLogPanel(JPanel):
    def __init__(self, engine, inspector=None):
        self.setLayout(BorderLayout())
        self._engine = engine
        self._inspector = inspector
        
        self._log_area = JTextArea()
        self._log_area.setEditable(False)
        self._log_area.setFont(FONT_MONO)
        
        self.add(JScrollPane(self._log_area), BorderLayout.CENTER)
        
        ctrl_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._btn_run = JButton("Run Workflow", actionPerformed=self._run_workflow)
        btn_clear = JButton("Clear Log", actionPerformed=self._clear_log)
        self._auto_clear_chk = JCheckBox("Auto-clear", True)
        
        ctrl_panel.add(self._btn_run)
        ctrl_panel.add(btn_clear)
        ctrl_panel.add(Box.createHorizontalStrut(10))
        ctrl_panel.add(self._auto_clear_chk)
        self.add(ctrl_panel, BorderLayout.NORTH)
        
        self._current_workflow = None

    def set_workflow(self, workflow):
        self._current_workflow = workflow
        self._btn_run.setEnabled(workflow is not None)

    def _clear_log(self, event):
        def update():
            self._log_area.setText("")
        invokeLater(update)
        if self._inspector:
            self._inspector.clear()

    def _run_workflow(self, event):
        wf = self._current_workflow
        if not wf: return
        
        if self._auto_clear_chk.isSelected():
            self._clear_log(None)
        
        def pre_run():
            self._log_area.append("\n--- Starting Execution: %s ---\n" % wf.name)
        invokeLater(pre_run)
        
        if self._inspector:
            self._inspector.clear()
        
        def run():
            try:
                self._engine.execute_workflow(wf, self._append_result)
                def post_run():
                    self._log_area.append("\n--- Execution Finished ---\n")
                invokeLater(post_run)
            except:
                print("FATAL ERROR in Workflow Runner:")
                traceback.print_exc()
                def err_run():
                    self._log_area.append("\n!!! FATAL ERROR IN RUNNER !!! Check Burp Console.\n")
                invokeLater(err_run)
        
        threading.Thread(target=run).start()

    def _append_result(self, result):
        result_str = str(result) + "\n"
        print("[ExecutionLogPanel] Appending result for step %d" % result.step_index)
        def update():
            self._log_area.append(result_str)
            self._log_area.setCaretPosition(self._log_area.getDocument().getLength())
        invokeLater(update)
        if self._inspector:
            self._inspector.add_result(result)


# =============================================================================
# MAIN EXTENSION CLASS
# =============================================================================

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IHttpListener, ISessionHandlingAction):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXTENSION_NAME)
        
        # Core Systems
        self.var_store = VariableStore()
        self.manager = WorkflowManager()
        self.engine = ExecutionEngine(callbacks, self._helpers, self.var_store, self.manager)
        
        # UI Components
        self.setup_ui()
        
        # Register listeners
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        callbacks.registerSessionHandlingAction(self)
        
        print(EXTENSION_NAME + " loaded successfully.")

    def setup_ui(self):
        self.main_panel = JPanel(BorderLayout())
        
        # Left: Flow List
        self.flow_list = FlowListPanel(self.manager, self._on_workflow_selected)
        
        # Middle: Step Editor
        self.step_editor = StepEditorPanel(self._on_workflow_modified)
        
        # Right: Log & Variables & Inspector
        right_panel = JPanel(BorderLayout())
        tabs = JTabbedPane()
        
        self.inspector_panel = ResponseInspectorPanel(self._callbacks)
        self.log_panel = ExecutionLogPanel(self.engine, self.inspector_panel)
        
        tabs.addTab("Execution Log", self.log_panel)
        tabs.addTab("Response Inspector", self.inspector_panel)
        
        self.var_table_model = VariablesTableModel(self.var_store)
        self.var_table = JTable(self.var_table_model)
        tabs.addTab("Variables", JScrollPane(self.var_table))
        
        right_panel.add(tabs, BorderLayout.CENTER)
        
        # Layout
        split_left = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self.flow_list, self.step_editor)
        split_left.setDividerLocation(200)
        
        split_main = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, split_left, right_panel)
        split_main.setDividerLocation(800)
        
        self.main_panel.add(split_main, BorderLayout.CENTER)

    def _on_workflow_selected(self, workflow):
        if hasattr(self.step_editor, "_workflow") and self.step_editor._workflow == workflow:
            return
        self.step_editor.load_workflow(workflow)
        self.log_panel.set_workflow(workflow)

    def _on_workflow_modified(self, workflow):
        self.manager.save_workflow(workflow)
        self.flow_list.refresh()

    # ITab
    def getTabCaption(self): return EXTENSION_NAME
    def getUiComponent(self): return self.main_panel

    # IContextMenuFactory
    def createMenuItems(self, invocation):
        items = []
        menu = JMenu("Send to FlipFlow")
        
        # Add to current workflow
        item_current = JMenuItem("Add to current workflow", actionPerformed=lambda e: self._import_request(invocation))
        menu.add(item_current)
        
        # Use a sub-menu for more workflows if needed
        # items.append(menu)
        return [menu]

    def _import_request(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages: return
        
        msg = messages[0]
        req_info = self._helpers.analyzeRequest(msg)
        service = msg.getHttpService()
        
        host = service.getHost()
        port = service.getPort()
        https = (service.getProtocol() == "https")
        req_str = self._helpers.bytesToString(msg.getRequest())
        
        self.step_editor.add_step_from_request(host, port, https, req_str)
        JOptionPane.showMessageDialog(None, "Request added to current workflow.")

    # IHttpListener
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # FlipFlow compatibility: Check for X-FlipFlow-Execute-Before header
        if messageIsRequest:
            request_bytes = messageInfo.getRequest()
            request_info = self._helpers.analyzeRequest(request_bytes)
            headers = request_info.getHeaders()
            
            target_wf = None
            new_headers = []
            for h in headers:
                if h.lower().startswith("x-flipflow-execute-before:"):
                    target_wf = h.split(":", 1)[1].strip()
                else:
                    new_headers.append(h)
            
            if target_wf:
                wf = self.manager.get_workflow(target_wf)
                if wf:
                    # Remove the header before sending
                    body = request_bytes[request_info.getBodyOffset():]
                    new_req = self._helpers.buildHttpMessage(new_headers, body)
                    messageInfo.setRequest(new_req)
                    
                    # Run the workflow
                    self.engine.execute_workflow(wf)

    # ISessionHandlingAction
    def getActionName(self): return EXTENSION_NAME
    def performAction(self, currentRequestResponse, macroItems):
        # Rule will be named "FlipFlow" in Burp
        # We look for a variable 'active_workflow' in the store to know what to run
        wf_name = self.var_store.get("active_workflow")
        if wf_name:
            wf = self.manager.get_workflow(wf_name)
            if wf:
                self.engine.execute_workflow(wf)
