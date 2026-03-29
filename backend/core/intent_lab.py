import subprocess
from backend.config import config

class IntentLab:
    def __init__(self, package_name):
        self.package_name = package_name

    def trigger_component(self, component_name, component_type):
        """Uses ADB to force-start an Activity or send a broadcast to a Receiver"""
        dev_id = config.ACTIVE_DEVICE_ID
        adb_base = ["adb"]
        if dev_id:
            adb_base += ["-s", dev_id]

        try:
            if component_type == 'activity':
                # adb shell am start -n pkg/name
                print(f"    [*] Starting Activity: {component_name}...")
                cmd = adb_base + ["shell", "am", "start", "-n", f"{self.package_name}/{component_name}"]
                subprocess.run(cmd, check=True, capture_output=True)
                return True
            elif component_type == 'receiver':
                # adb shell am broadcast -n pkg/name
                print(f"    [*] Sending Broadcast to: {component_name}...")
                cmd = adb_base + ["shell", "am", "broadcast", "-n", f"{self.package_name}/{component_name}"]
                subprocess.run(cmd, check=True, capture_output=True)
                return True
            return False
        except Exception as e:
            print(f"    [-] Trigger failed: {e}")
            return False
