import os
import re
import subprocess
import sys
from backend.config import config

class APKScanner:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.output_dir = os.path.join(config.TEMP_DECOMPILED_PATH, os.path.basename(apk_path).replace(".apk", ""))

    def decompile(self):
        """Decompiles the APK using pyapktool via command line"""
        print(f"Decompiling {self.apk_path} to {self.output_dir}...")
        if not os.path.exists(config.TEMP_DECOMPILED_PATH):
            os.makedirs(config.TEMP_DECOMPILED_PATH)
        
        # Call pyapktool's Apktool class directly via python -c
        try:
            cmd = f"{sys.executable} -c \"from pyapktool.pyapktool import Apktool; a=Apktool('pyapktool_tools'); a.get(); a.unpack(r'{self.apk_path}', r'{self.output_dir}')\""
            subprocess.run(cmd, check=True, shell=True)
            return True
        except Exception as e:
            print(f"Decompilation failed: {e}")
            return False

    def find_security_logic(self):
        """Searches for SSL pinning and root detection patterns in Smali files"""
        patterns = {
            "ssl_pinning": [
                r"X509TrustManager",
                r"checkClientTrusted",
                r"checkServerTrusted",
                r"SSLContext",
                r"CertificatePinner"
            ],
            "root_detection": [
                r"/system/app/Superuser.apk",
                r"root-checker",
                r"which su",
                r"test-keys"
            ]
        }
        
        results = []
        if not os.path.exists(self.output_dir):
            return results

        for root, dirs, files in os.walk(self.output_dir):
            for file in files:
                if file.endswith(".smali"):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for category, regex_list in patterns.items():
                            for regex in regex_list:
                                if re.search(regex, content, re.IGNORECASE):
                                    match = re.search(regex, content, re.IGNORECASE)
                                    start = max(0, content.rfind('.method', 0, match.start()))
                                    end = content.find('.end method', match.end()) + 11
                                    if start != -1 and end != -1:
                                        results.append({
                                            "file": file_path,
                                            "category": category,
                                            "code": content[start:end]
                                        })
        return results
