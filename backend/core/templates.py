import os
from backend.config import config

class HookTemplates:
    TEMPLATES = {
        "SSL Pinning (Universal)": """
Java.perform(function() {
    var array_list = Java.use("java.util.ArrayList");
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");

    TrustManagerImpl.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String').implementation = function (chain, authType, host) {
        console.log("[+] Bypassing SSL Pinning for: " + host);
        return array_list.$new();
    };
});
""",
        "Root Detection Bypass": """
Java.perform(function() {
    var File = Java.use("java.io.File");
    File.exists.implementation = function () {
        var path = this.getPath();
        if (path.includes("su") || path.includes("superuser") || path.includes("magisk")) {
            console.log("[+] Bypassing Root Check for: " + path);
            return false;
        }
        return this.exists();
    };
});
""",
        "WebView Logger": """
Java.perform(function() {
    var WebView = Java.use("android.webkit.WebView");
    WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
        console.log("[*] WebView loading URL: " + url);
        this.loadUrl(url);
    };
});
""",
        "Keystore Logger": """
Java.perform(function() {
    var KeyStore = Java.use("java.security.KeyStore");
    KeyStore.getEntry.overload('java.lang.String', 'java.security.KeyStore$ProtectionParameter').implementation = function (alias, prot) {
        console.log("[*] Accessing KeyStore entry: " + alias);
        return this.getEntry(alias, prot);
    };
});
"""
    }

    def list_templates(self):
        return list(self.TEMPLATES.keys())

    def generate_hook(self, template_name):
        return self.TEMPLATES.get(template_name, "")

    def save_hook(self, hook_code, filename="generated_hook.js"):
        if not os.path.exists(config.FRIDA_SCRIPTS_PATH):
            os.makedirs(config.FRIDA_SCRIPTS_PATH)
        path = os.path.join(config.FRIDA_SCRIPTS_PATH, filename)
        with open(path, "w") as f:
            f.write(hook_code)
        return path
