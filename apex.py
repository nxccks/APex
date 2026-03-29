#!/usr/bin/env python3
import argparse
import sys
import json
import os
import shutil
import subprocess
import threading
import time
from backend.core.scanner import APKScanner
from backend.core.dynamic import FridaOrchestrator
from backend.core.dumper import ADBDumper
from backend.core.explorer import LootExplorer
from backend.core.intent_lab import IntentLab
from backend.core.templates import HookTemplates
from backend.config import config
from backend.core.utils import list_adb_devices, list_installed_packages

# Global indentation
INDENT = "    "

BANNER = r"""
    /   |  / __ \___  _  __
   / /| | / /_/ / _ \| |/_/
  / ___ |/ ____/  __/>  <  
 /_/  |_/_/    \___/_/|_|  
"""

def print_header():
    print()
    for line in BANNER.split('\n'):
        if line.strip():
            print(INDENT + line)
    print()

def c_input(prompt_text="", newline=True, indicator="> "):
    if prompt_text:
        if newline:
            print(INDENT + f"{prompt_text}")
            return input(INDENT + indicator).strip()
        else:
            return input(INDENT + f"{prompt_text} {indicator}").strip()
    return input(INDENT + indicator).strip()

def print_progress_bar(current, total, prefix="Analyzing APK"):
    width = 40
    percent = float(current) * 100 / total
    filled = int(width * current // total)
    bar = "█" * filled + "-" * (width - filled)
    sys.stdout.write(f"\r{INDENT}{prefix}: |{bar}| {percent:.1f}%")
    sys.stdout.flush()
    if current == total: print()

def run_task_with_loading(task_func, prefix="Decompiling APK"):
    done = False
    result = [None]
    def target():
        nonlocal done
        try: result[0] = task_func()
        except Exception as e: result[0] = e
        done = True
    thread = threading.Thread(target=target)
    thread.start()
    current = 0
    while not done:
        if current < 95: current += 1
        print_progress_bar(current, 100, prefix=prefix)
        time.sleep(0.1)
    if isinstance(result[0], Exception):
        print_progress_bar(0, 100, prefix=prefix)
        return result[0]
    print_progress_bar(100, 100, prefix=prefix)
    return result[0]

def print_report(data):
    print("\n" + INDENT + "=" * 60)
    print(INDENT + "MOBILE SECURITY SCAN REPORT")
    print(INDENT + "=" * 60 + "\n")
    m = data["Manifest Risks"]
    print(INDENT + "[ MANIFEST CONFIGURATION ]")
    print(INDENT + f"  - Debuggable:      {'[!!] YES' if m['debuggable'] else 'No'}")
    print(INDENT + f"  - Allow Backup:    {'[!] YES' if m['allow_backup'] else 'No'}")
    print(INDENT + f"  - Cleartext HTTP:  {'[!] YES' if m['cleartext_traffic'] else 'No'}")
    if m["permissions"]: print(INDENT + "  - Sensitive Perms: " + ", ".join(m["permissions"]))
    if m["exported_components"]:
        print(INDENT + "  - Exported Components:")
        for comp in m["exported_components"][:5]: print(INDENT + f"    * {comp}")
    print()
    if data.get("Sensitive Assets"):
        print(INDENT + "[ SENSITIVE FILES IN ASSETS ]")
        for asset in data["Sensitive Assets"]: print(INDENT + f"  - [!] {asset}")
        print()
    print(INDENT + "[ CODE-LEVEL FINDINGS ]")
    findings_found = False
    for category, findings in data["Code Findings"].items():
        if findings:
            findings_found = True
            print(INDENT + f"  > {category}:")
            grouped = {}
            for f in findings:
                if f["type"] not in grouped: grouped[f["type"]] = []
                grouped[f["type"]].append(f)
            for ftype, instances in grouped.items():
                print(INDENT + f"    - {ftype} ({len(instances)} instances)")
                for inst in instances[:2]:
                    print(INDENT + f"      @ {inst['file']}")
                    if inst['matches']:
                        val = inst['matches'][0][:50] + "..." if len(inst['matches'][0]) > 50 else inst['matches'][0]
                        print(INDENT + f"        Match: {val}")
    if not findings_found: print(INDENT + "  - No critical code vulnerabilities detected.")
    print("\n" + INDENT + "=" * 60)

def select_package():
    packages = list_installed_packages(config.ACTIVE_DEVICE_ID)
    if not packages: return None
    print(INDENT + "[ SELECT PACKAGE ]")
    for i, pkg in enumerate(packages): print(INDENT + f"{i+1}. {pkg}")
    print()
    sel = c_input("Enter number")
    try: return packages[int(sel)-1]
    except: return None

def select_previous_session():
    if not os.path.exists(config.TEMP_DECOMPILED_PATH): return None
    prev_scans = [d for d in os.listdir(config.TEMP_DECOMPILED_PATH) if os.path.isdir(os.path.join(config.TEMP_DECOMPILED_PATH, d))]
    if not prev_scans: return None
    print(INDENT + "[ SELECT PREVIOUS SESSION ]")
    for i, s in enumerate(prev_scans): print(INDENT + f"{i+1}. {s}")
    print()
    s_sel = c_input("Enter number")
    try: return os.path.join(config.TEMP_DECOMPILED_PATH, prev_scans[int(s_sel)-1])
    except: return None

def interactive_menu():
    devices = list_adb_devices()
    if devices: config.ACTIVE_DEVICE_ID = devices[0]["id"]

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print_header()
        status = "CONNECTED" if config.ACTIVE_DEVICE_ID else "NOT CONNECTED"
        dev_id = config.ACTIVE_DEVICE_ID if config.ACTIVE_DEVICE_ID else "None"
        print(INDENT + f"[ STATUS: {status} ]")
        print(INDENT + f"[ ACTIVE DEVICE: {dev_id} ]\n")
        print(INDENT + "[ MAIN MENU ]\n")

        menu_items = [
            "1. Scan APK (Static Analysis)",
            "2. Inject Frida Script (Dynamic)",
            "3. Intent Lab (Component Testing)",
            "4. Exfiltrate App Data (ADB)",
            "5. Loot Explorer (Browse Data)",
            "6. Hook Template Generator",
            "7. List Local Scripts",
            "8. Select/Change Device",
            "0. Exit"
        ]
        for item in menu_items: print(INDENT + item)
        print("\n" + INDENT + "-" * 20)
        choice = c_input("Select an option")
        print()

        if choice == '1':
            dir_path = select_previous_session()
            if dir_path:
                scanner = APKScanner(existing_dir=dir_path)
                print_report(scanner.find_security_logic(progress_callback=print_progress_bar))
            else:
                path = c_input("Enter APK path")
                if os.path.exists(path):
                    scanner = APKScanner(apk_path=path)
                    if run_task_with_loading(scanner.decompile, prefix="Decompiling APK"):
                        print_report(scanner.find_security_logic(progress_callback=print_progress_bar))
                    else: print(INDENT + "[-] Decompilation failed.")
            c_input("Press Enter to return to menu", newline=False, indicator="")

        elif choice == '2':
            if not config.ACTIVE_DEVICE_ID: continue
            pkg = select_package()
            if pkg:
                orch = FridaOrchestrator(pkg)
                scripts = orch.list_scripts()
                if scripts:
                    print(INDENT + "[ SELECT SCRIPT ]")
                    for i, s in enumerate(scripts): print(INDENT + f"{i+1}. {s}")
                    print()
                    s_sel = c_input("Enter number")
                    try: orch.attach_and_inject(scripts[int(s_sel)-1])
                    except: pass

        elif choice == '3':
            if not config.ACTIVE_DEVICE_ID: continue
            pkg = select_package()
            if pkg:
                print(f"\n{INDENT}[*] Fetching exported components for {pkg}...")
                # We need a scanner object to find the manifest findings
                # For simplicity, we assume the user has scanned the app once
                lab = IntentLab(pkg)
                print(INDENT + "[ INTENT LAB - MANUAL TRIGGER ]")
                comp_name = c_input("Enter Component Name (from Scan Report)")
                comp_type = c_input("Type (activity/receiver)")
                if comp_name and comp_type:
                    lab.trigger_component(comp_name, comp_type)
            c_input("Press Enter to return to menu", newline=False, indicator="")

        elif choice == '4':
            if not config.ACTIVE_DEVICE_ID: continue
            pkg = select_package()
            if pkg:
                dumper = ADBDumper(pkg)
                results = dumper.pull_data()
                print("\n" + INDENT + "[+] Exfiltration Results:")
                for r in results:
                    status = "V" if r['status'] == 'pulled' else "X"
                    print(f"{INDENT}  {status} {r['target']}")
            c_input("Press Enter to return to menu", newline=False, indicator="")

        elif choice == '5':
            explorer = LootExplorer(config.DOWNLOADS_PATH)
            sessions = explorer.list_sessions()
            if not sessions:
                print(INDENT + "[-] No exfiltrated data found in downloads/ folder.")
            else:
                print(INDENT + "[ SELECT LOOT SESSION ]")
                for i, s in enumerate(sessions): print(INDENT + f"{i+1}. {s}")
                print()
                s_sel = c_input("Enter number")
                try:
                    pkg_name = sessions[int(s_sel)-1]
                    files = explorer.list_files(pkg_name)
                    print(f"\n{INDENT}[ FILES IN {pkg_name} ]")
                    for i, f in enumerate(files): print(INDENT + f"{i+1}. {f}")
                    print()
                    f_sel = c_input("Select file to view/explore")
                    file_rel_path = files[int(f_sel)-1]
                    
                    if file_rel_path.endswith(".db"):
                        db_data = explorer.explore_db(pkg_name, file_rel_path)
                        for table, content in db_data.get("tables", {}).items():
                            print(f"\n{INDENT}--- TABLE: {table} ---")
                            print(INDENT + " | ".join(content["columns"]))
                            for row in content["rows"]: print(INDENT + " | ".join(map(str, row)))
                    else:
                        print(f"\n{INDENT}--- FILE CONTENT ---")
                        print(explorer.view_xml(pkg_name, file_rel_path))
                except: print(INDENT + "[-] Invalid selection.")
            c_input("Press Enter to return to menu", newline=False, indicator="")

        elif choice == '6':
            templates = HookTemplates()
            list_t = templates.list_templates()
            print(INDENT + "[ SELECT HOOK TEMPLATE ]")
            for i, t in enumerate(list_t): print(INDENT + f"{i+1}. {t}")
            print()
            t_sel = c_input("Enter number")
            try:
                name = list_t[int(t_sel)-1]
                code = templates.generate_hook(name)
                fname = name.lower().replace(" ", "_").replace("(", "").replace(")", "") + ".js"
                path = templates.save_hook(code, fname)
                print(f"\n{INDENT}[+] Template generated and saved to: {path}")
                print(INDENT + "-" * 20)
                for line in code.split('\n'): print(INDENT + line)
                print(INDENT + "-" * 20)
            except: print(INDENT + "[-] Invalid selection.")
            c_input("Press Enter to return to menu", newline=False, indicator="")

        elif choice == '7':
            scripts = FridaOrchestrator(None).list_scripts()
            print("\n" + INDENT + "[+] Script Library:\n")
            for s in scripts: print(INDENT + f"  - {s}")
            c_input("Press Enter to return to menu", newline=False, indicator="")

        elif choice == '8':
            devices = list_adb_devices()
            if devices:
                print(INDENT + "[ SELECT DEVICE ]")
                for i, dev in enumerate(devices): print(INDENT + f"{i+1}. {dev['id']} ({dev['status']})")
                print()
                sel = c_input("Enter number")
                try: config.ACTIVE_DEVICE_ID = devices[int(sel)-1]["id"]
                except: pass

        elif choice == '0': break

def main():
    parser = argparse.ArgumentParser(description="🛡️  APex CLI", add_help=False)
    parser.add_argument('-h', '--help', action='help')
    subparsers = parser.add_subparsers(dest="command")
    if len(sys.argv) == 1: interactive_menu()
    else:
        args = parser.parse_args()
        # Non-interactive mode support can be added back here if needed

if __name__ == "__main__": main()
