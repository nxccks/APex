import frida
import os
from backend.config import config

class FridaOrchestrator:
    def __init__(self, package_name=None):
        self.package_name = package_name
        self.device = None
        self.session = None

    def _get_device(self):
        """Lazily connects to the USB device when needed"""
        if self.device is None:
            try:
                self.device = frida.get_usb_device(timeout=2)
            except Exception as e:
                print(f"[-] Frida Error: Could not find USB device. Ensure frida-server is running. ({e})")
                raise e
        return self.device

    def list_scripts(self):
        """Lists available Frida scripts in the user's directory (No device needed)"""
        if not os.path.exists(config.FRIDA_SCRIPTS_PATH):
            os.makedirs(config.FRIDA_SCRIPTS_PATH)
        return [f for f in os.listdir(config.FRIDA_SCRIPTS_PATH) if f.endswith(".js")]

    def attach_and_inject(self, script_name):
        """Attaches to the process and injects the selected script (Device required)"""
        script_path = os.path.join(config.FRIDA_SCRIPTS_PATH, script_name)
        if not os.path.exists(script_path):
            print(f"[-] Error: Script {script_name} not found.")
            return False

        with open(script_path, 'r') as f:
            script_content = f.read()

        try:
            device = self._get_device()
            self.session = device.attach(self.package_name)
            script = self.session.create_script(script_content)
            script.load()
            return True
        except Exception as e:
            print(f"[-] Injection failed: {e}")
            return False
