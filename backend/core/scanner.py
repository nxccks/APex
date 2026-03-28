import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from backend.config import config

class APKScanner:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.output_dir = os.path.normpath(os.path.join(config.TEMP_DECOMPILED_PATH, os.path.basename(apk_path).replace(".apk", "")))
        self.manifest_path = os.path.join(self.output_dir, "AndroidManifest.xml")
        self.apktool_jar = os.path.join("pyapktool_tools", "apktool.jar")

    def decompile(self):
        """Decompiles the APK using the managed apktool.jar directly"""
        if not os.path.exists(config.TEMP_DECOMPILED_PATH):
            os.makedirs(config.TEMP_DECOMPILED_PATH)

        if not os.path.exists(self.apktool_jar):
            try:
                import pyapktool.pyapktool as pat
                pat.Apktool("pyapktool_tools").get()
            except ImportError:
                return False

        try:
            cmd = ["java", "-jar", self.apktool_jar, "d", self.apk_path, "-o", self.output_dir, "-f"]
            subprocess.run(cmd, check=True, shell=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def find_manifest_risks(self):
        """Parses AndroidManifest.xml for misconfigurations"""
        risks = {
            "permissions": [],
            "exported_components": [],
            "debuggable": False,
            "allow_backup": True,
            "cleartext_traffic": False
        }
        if not os.path.exists(self.manifest_path):
            return risks

        try:
            tree = ET.parse(self.manifest_path)
            root = tree.getroot()
            ns = {'android': 'http://schemas.android.com/apk/res/android'}

            application = root.find('application')
            if application is not None:
                risks["debuggable"] = application.get('{http://schemas.android.com/apk/res/android}debuggable') == "true"
                risks["allow_backup"] = application.get('{http://schemas.android.com/apk/res/android}allowBackup') != "false"
                risks["cleartext_traffic"] = application.get('{http://schemas.android.com/apk/res/android}usesCleartextTraffic') == "true"

                for tag in ['activity', 'service', 'receiver', 'provider']:
                    for comp in application.findall(tag):
                        if comp.get('{http://schemas.android.com/apk/res/android}exported') == "true":
                            risks["exported_components"].append(f"{tag.capitalize()}: {comp.get('{http://schemas.android.com/apk/res/android}name')}")

            dangerous_perms = ["READ_SMS", "RECEIVE_SMS", "READ_CONTACTS", "CAMERA", "ACCESS_FINE_LOCATION", "RECORD_AUDIO", "READ_EXTERNAL_STORAGE"]
            for perm in root.findall('uses-permission'):
                name = perm.get('{http://schemas.android.com/apk/res/android}name', "").split('.')[-1]
                if name in dangerous_perms:
                    risks["permissions"].append(name)
        except:
            pass
        return risks

    def find_security_logic(self):
        """Comprehensive scan for vulnerabilities and secrets"""
        patterns = {
            "Secrets & API Keys": {
                "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
                "AWS Access Key": r"AKIA[0-9A-Z]{16}",
                "Firebase URL": r"https://.*\.firebaseio\.com",
                "Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
                "Generic Secret": r"(?i)(api_key|secret_key|auth_token|db_password)\s*[:=]\s*['\"]([^'\"]+)['\"]"
            },
            "Network & API Endpoints": {
                "HTTP Endpoint": r"http://[a-zA-Z0-9\./_-]+",
                "Internal IP": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
            },
            "Insecure Code Patterns": {
                "Insecure WebView": r"setJavaScriptEnabled\(1\)|setAllowFileAccess\(1\)",
                "Weak Crypto (MD5/SHA1)": r"MD5|SHA1",
                "World Readable File": r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE"
            },
            "Security Protections": {
                "SSL Pinning Logic": r"X509TrustManager|checkServerTrusted|CertificatePinner",
                "Root Detection": r"Superuser\.apk|root-checker|which su|test-keys"
            }
        }
        
        report = {"Manifest Risks": self.find_manifest_risks(), "Code Findings": {}}
        
        for root, dirs, files in os.walk(self.output_dir):
            for file in files:
                if file.endswith(".smali"):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for category, sub_patterns in patterns.items():
                            if category not in report["Code Findings"]: report["Code Findings"][category] = []
                            for name, regex in sub_patterns.items():
                                matches = re.findall(regex, content)
                                if matches:
                                    # Clean up matches for better reporting
                                    clean_matches = list(set([str(m[1]) if isinstance(m, tuple) else str(m) for m in matches]))
                                    report["Code Findings"][category].append({"type": name, "file": os.path.relpath(file_path, self.output_dir), "matches": clean_matches[:5]})
        return report
