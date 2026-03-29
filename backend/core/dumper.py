import subprocess
import os
import time
from backend.config import config

class ADBDumper:
    def __init__(self, package_name):
        self.package_name = package_name
        self.output_dir = os.path.join(config.DOWNLOADS_PATH, package_name)
        self.tmp_dir = f"/data/local/tmp/apex_{int(time.time())}"

    def pull_data(self):
        """Pulls sensitive data from protected directories using root hop"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        dev_id = config.ACTIVE_DEVICE_ID
        adb_base = ["adb"]
        if dev_id: adb_base += ["-s", dev_id]

        targets = ["databases", "shared_prefs", "lib"]
        results = []

        try:
            # 1. Create a temporary world-readable directory on the device
            subprocess.run(adb_base + ["shell", "su", "-c", f"mkdir -p {self.tmp_dir}"], check=True)
            subprocess.run(adb_base + ["shell", "su", "-c", f"chmod 777 {self.tmp_dir}"], check=True)

            for target in targets:
                source_path = f"/data/data/{self.package_name}/{target}"
                dest_path = f"{self.tmp_dir}/{target}"
                
                # 2. Copy protected data to the temp directory via root
                cp_cmd = adb_base + ["shell", "su", "-c", f"cp -r {source_path} {dest_path}"]
                cp_proc = subprocess.run(cp_cmd, capture_output=True)
                
                if cp_proc.returncode == 0:
                    # 3. Make the copied data readable
                    subprocess.run(adb_base + ["shell", "su", "-c", f"chmod -R 777 {dest_path}"], check=True)
                    
                    # 4. Pull from temp to local
                    pull_cmd = adb_base + ["pull", dest_path, self.output_dir]
                    pull_proc = subprocess.run(pull_cmd, capture_output=True)
                    
                    if pull_proc.returncode == 0:
                        results.append({"target": source_path, "status": "pulled"})
                    else:
                        results.append({"target": source_path, "status": "failed", "error": "ADB Pull failed"})
                else:
                    results.append({"target": source_path, "status": "failed", "error": "Copy failed (Empty or protected)"})

        except Exception as e:
            print(f"    [-] Exfiltration Error: {e}")
        finally:
            # 5. Cleanup
            subprocess.run(adb_base + ["shell", "su", "-c", f"rm -rf {self.tmp_dir}"], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return results
