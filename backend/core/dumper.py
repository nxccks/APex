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
        """Pulls sensitive data using a highly compatible root-hop method"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        dev_id = config.ACTIVE_DEVICE_ID
        adb_prefix = ["adb"]
        if dev_id: adb_prefix += ["-s", dev_id]

        targets = ["databases", "shared_prefs", "lib"]
        results = []

        try:
            # 1. Create temp dir using a piped command for maximum compatibility
            setup_script = f"mkdir -p {self.tmp_dir} && chmod 777 {self.tmp_dir}\n"
            subprocess.run(adb_prefix + ["shell", "su"], input=setup_script.encode(), check=True, capture_output=True)
            print(f"    [*] Initializing root-hop at {self.tmp_dir}...")

            for target in targets:
                source_path = f"/data/data/{self.package_name}/{target}"
                dest_path = f"{self.tmp_dir}/{target}"
                
                # 2. Copy and set permissions via piped root shell
                print(f"    [*] Copying {target}...")
                cp_script = f"cp -r {source_path} {dest_path} 2>/dev/null && chmod -R 777 {dest_path}\n"
                
                cp_proc = subprocess.run(adb_prefix + ["shell", "su"], input=cp_script.encode(), capture_output=True)
                
                # Check if the destination directory was actually created (meaning copy succeeded)
                check_cmd = adb_prefix + ["shell", f"ls {dest_path}"]
                check_proc = subprocess.run(check_cmd, capture_output=True, text=True)

                if "No such file" not in check_proc.stdout and "No such file" not in check_proc.stderr:
                    # 3. Pull from temp to local
                    pull_cmd = adb_prefix + ["pull", dest_path, self.output_dir]
                    pull_proc = subprocess.run(pull_cmd, capture_output=True, text=True)
                    
                    if pull_proc.returncode == 0:
                        results.append({"target": source_path, "status": "pulled"})
                    else:
                        err = pull_proc.stderr.strip().split('\n')[0]
                        results.append({"target": source_path, "status": "failed", "error": f"Pull failed: {err}"})
                else:
                    results.append({"target": source_path, "status": "failed", "error": "Not found or protected"})

        except Exception as e:
            print(f"    [-] Exfiltration Error: {e}")
        finally:
            # 4. Cleanup via piped shell
            cleanup_script = f"rm -rf {self.tmp_dir}\n"
            subprocess.run(adb_prefix + ["shell", "su"], input=cleanup_script.encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


        return results
