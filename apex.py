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
from backend.ai.provider import AIProviderFactory
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
    if current == total:
        print()

def run_task_with_loading(task_func, prefix="Decompiling APK"):
    done = False
    result = [None]
    def target():
        nonlocal done
        result[0] = task_func()
        done = True
    thread = threading.Thread(target=target)
    thread.start()
    current = 0
    while not done:
        if current < 95: current += 1
        print_progress_bar(current, 100, prefix=prefix)
        time.sleep(0.1)
    print_progress_bar(100, 100, prefix=prefix)
    return result[0]

def print_report(data):
    print("\n" + INDENT + "=" * 60)
    print(INDENT + "MOBILE SECURITY SCAN REPORT")
    print(INDENT + "=" * 60 + "\n")
    
    # 1. Manifest Analysis
    m = data["Manifest Risks"]
    print(INDENT + "[ MANIFEST CONFIGURATION ]")
    print(INDENT + f"  - Debuggable:      {'[!!] YES' if m['debuggable'] else 'No'}")
    print(INDENT + f"  - Allow Backup:    {'[!] YES' if m['allow_backup'] else 'No'}")
    print(INDENT + f"  - Cleartext HTTP:  {'[!] YES' if m['cleartext_traffic'] else 'No'}")
    if m["permissions"]:
        print(INDENT + "  - Sensitive Perms: " + ", ".join(m["permissions"]))
    if m["exported_components"]:
        print(INDENT + "  - Exported Components:")
        for comp in m["exported_components"][:5]:
            print(INDENT + f"    * {comp}")
    print()

    # 2. Asset Analysis
    if data.get("Sensitive Assets"):
        print(INDENT + "[ SENSITIVE FILES IN ASSETS ]")
        for asset in data["Sensitive Assets"]:
            print(INDENT + f"  - [!] {asset}")
        print()

    # 3. Code Findings
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
    if not packages:
        print(INDENT + "[-] No 3rd party packages found on device.")
        return None
    print(INDENT + "[ SELECT PACKAGE ]")
    for i, pkg in enumerate(packages):
        print(INDENT + f"{i+1}. {pkg}")
    sel = c_input("\nEnter number")
    try: return packages[int(sel)-1]
    except:
        print(INDENT + "[-] Invalid selection.")
        return None

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
            "3. Generate AI Bypass Hook",
            "4. Exfiltrate App Data (ADB)",
            "5. List Local Scripts",
            "6. Select/Change Device",
            "0. Exit"
        ]
        for item in menu_items: print(INDENT + item)
        print("\n" + INDENT + "-" * 20)
        choice = c_input("Select an option")
        print()

        if choice == '1':
            path = c_input("Enter APK path")
            if os.path.exists(path):
                scanner = APKScanner(path)
                if run_task_with_loading(scanner.decompile, prefix="Decompiling APK"):
                    report = scanner.find_security_logic(progress_callback=print_progress_bar)
                    print_report(report)
                else: print(INDENT + "[-] Decompilation failed.")
            else: print(INDENT + "[-] File not found.")

        elif choice == '2':
            if not config.ACTIVE_DEVICE_ID: continue
            pkg = select_package()
            if pkg:
                orch = FridaOrchestrator(pkg)
                scripts = orch.list_scripts()
                if not scripts: print(INDENT + "[-] No scripts found.")
                else:
                    print(INDENT + "[ SELECT SCRIPT ]")
                    for i, s in enumerate(scripts): print(INDENT + f"{i+1}. {s}")
                    s_sel = c_input("\nEnter number")
                    try: orch.attach_and_inject(scripts[int(s_sel)-1])
                    except: print(INDENT + "[-] Invalid selection.")

        elif choice == '3':
            file_path = c_input("Enter path to Smali snippet file")
            if os.path.exists(file_path):
                with open(file_path, 'r') as f: code = f.read()
                cat = c_input("Category (default: ssl_pinning)") or "ssl_pinning"
                try:
                    provider = AIProviderFactory.get_provider()
                    hook = provider.generate_hook(code, cat)
                    out = os.path.join(config.FRIDA_SCRIPTS_PATH, "ai_generated.js")
                    if not os.path.exists(config.FRIDA_SCRIPTS_PATH): os.makedirs(config.FRIDA_SCRIPTS_PATH)
                    with open(out, "w") as f: f.write(hook)
                    print(f"\n{INDENT}[+] Saved to {out}\n{INDENT}" + "-" * 20)
                    for line in hook.split('\n'): print(INDENT + line)
                    print(INDENT + "-" * 20)
                except Exception as e: print(INDENT + f"[-] AI Error: {e}")

        elif choice == '4':
            if not config.ACTIVE_DEVICE_ID: continue
            pkg = select_package()
            if pkg:
                dumper = ADBDumper(pkg)
                results = dumper.pull_data()
                print("\n" + INDENT + "[+] Exfiltration Results:")
                for r in results:
                    status = "V" if r['status'] == 'pulled' else "X"
                    print(INDENT + f"  {status} {r['target']}")

        elif choice == '5':
            scripts = FridaOrchestrator(None).list_scripts()
            print("\n" + INDENT + "[+] Script Library:\n")
            for s in scripts: print(INDENT + f"  - {s}")

        elif choice == '6':
            devices = list_adb_devices()
            if not devices: print(INDENT + "[-] No devices found.")
            else:
                print(INDENT + "[ SELECT DEVICE ]")
                for i, dev in enumerate(devices): print(INDENT + f"{i+1}. {dev['id']} ({dev['status']})")
                sel = c_input("Enter number")
                try: config.ACTIVE_DEVICE_ID = devices[int(sel)-1]["id"]
                except: print(INDENT + "[-] Invalid selection.")

        elif choice == '0': break
        print()
        c_input("Press Enter to return to menu", newline=False, indicator="")

def main():
    parser = argparse.ArgumentParser(description="🛡️  APex CLI", add_help=False)
    parser.add_argument('-h', '--help', action='help')
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("scan").add_argument("apk_path")
    subparsers.add_parser("inject").add_argument("package_name")
    subparsers.add_parser("list-scripts")
    subparsers.add_parser("exfiltrate").add_argument("package_name")
    subparsers.add_parser("generate-hook").add_argument("smali_file")
    if len(sys.argv) == 1: interactive_menu()
    else:
        args = parser.parse_args()
        if args.command == "scan":
            scanner = APKScanner(args.apk_path)
            if scanner.decompile(): print_report(scanner.find_security_logic(progress_callback=print_progress_bar))

if __name__ == "__main__": main()
