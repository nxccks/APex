import os
import subprocess
from backend.config import config

class FridaOrchestrator:
    def __init__(self, package_name=None):
        self.package_name = package_name

    def list_scripts(self):
        """Lists available Frida scripts in the user's directory"""
        if not os.path.exists(config.FRIDA_SCRIPTS_PATH):
            os.makedirs(config.FRIDA_SCRIPTS_PATH)
        return [f for f in os.listdir(config.FRIDA_SCRIPTS_PATH) if f.endswith(".js")]

    def attach_and_inject(self, script_name):
        """Uses the native Frida CLI and ensures full termination on exit"""
        script_path = os.path.join(config.FRIDA_SCRIPTS_PATH, script_name)
        if not os.path.exists(script_path):
            print(f"[-] Error: Script {script_name} not found.")
            return False

        # Build the native frida command
        cmd = ["frida", "-U", "-f", self.package_name, "-l", script_path]
        if config.ACTIVE_DEVICE_ID:
            cmd = ["frida", "-D", config.ACTIVE_DEVICE_ID, "-f", self.package_name, "-l", script_path]

        print(f"    [*] Launching Frida session for {self.package_name}...")
        print("    [*] Press Ctrl+C to stop Frida and terminate the app.\n")

        try:
            # Execute native frida (this is blocking)
            subprocess.call(cmd)
            return True
        except KeyboardInterrupt:
            return True
        except Exception as e:
            print(f"\n    [-] Failed to launch native Frida CLI: {e}")
            return False
        finally:
            # MULTI-LAYER TERMINATION: Hard-kill the app through all possible channels
            adb_base = ["adb"]
            if config.ACTIVE_DEVICE_ID:
                adb_base += ["-s", config.ACTIVE_DEVICE_ID]
            
            print(f"    [*] Hard-terminating {self.package_name}...")
            
            # Layer 1: Standard Force-Stop
            subprocess.run(adb_base + ["shell", "am", "force-stop", self.package_name], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Layer 2: Root Force-Stop (Ensures background services are killed)
            subprocess.run(adb_base + ["shell", "su", "-c", f"\"am force-stop {self.package_name}\""], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Layer 3: Process Kill (Fallback for stubborn processes)
            subprocess.run(adb_base + ["shell", "su", "-c", f"\"pkill -f {self.package_name}\""], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            print(f"    [+] Session for {self.package_name} fully terminated.")
