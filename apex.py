#!/usr/bin/env python3
import argparse
import sys
import json
import os
import shutil
import subprocess
from backend.core.scanner import APKScanner
from backend.core.dynamic import FridaOrchestrator
from backend.core.dumper import ADBDumper
from backend.ai.provider import AIProviderFactory
from backend.config import config

BANNER = r"""
    /   |  / __ \___  _  __
   / /| | / /_/ / _ \| |/_/
  / ___ |/ ____/  __/>  <  
 /_/  |_/_/    \___/_/|_|  
"""

def get_width():
    return shutil.get_terminal_size().columns

def print_header():
    width = get_width()
    print()
    for line in BANNER.split('\n'):
        if line.strip():
            print(line.center(width))
    print()

def c_input(prompt_text="", show_indicator=True):
    """Displays a centered prompt and centers the input cursor on the line below it"""
    width = get_width()
    if prompt_text:
        print(prompt_text.center(width))
    
    indicator = "> " if show_indicator else ""
    padding = (width - len(indicator)) // 2
    return input(" " * padding + indicator).strip()

def interactive_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print_header()
        width = get_width()
        
        print("[ MAIN MENU ]".center(width))
        print()

        menu_items = [
            "1. Scan APK (Static Analysis)",
            "2. Inject Frida Script (Dynamic)",
            "3. Generate AI Bypass Hook",
            "4. Exfiltrate App Data (ADB)",
            "5. List Local Scripts",
            "6. Select/Change Device",
            "0. Exit"
        ]
        
        for item in menu_items:
            print(item.center(width))
            
        print("\n" + ("-" * 20).center(width))
        
        choice = c_input("Select an option")

        print()

        if choice == '1':
            path = c_input("Enter APK path")
            if os.path.exists(path):
                scanner = APKScanner(path)
                if scanner.decompile():
                    findings = scanner.find_security_logic()
                    print()
                    print("[+] Findings:".center(width))
                    print(json.dumps(findings, indent=2))
                else: print("[-] Decompilation failed.".center(width))
            else: print("[-] File not found.".center(width))

        elif choice == '2':
            pkg = c_input("Enter Package Name")
            script = c_input("Enter Script Name")
            orch = FridaOrchestrator(pkg)
            if orch.attach_and_inject(script): print("[+] Injection Success!".center(width))
            else: print("[-] Injection Failed.".center(width))

        elif choice == '3':
            file_path = c_input("Enter path to Smali snippet file")
            if os.path.exists(file_path):
                with open(file_path, 'r') as f: code = f.read()
                cat = c_input("Category (default: ssl_pinning)") or "ssl_pinning"
                try:
                    provider = AIProviderFactory.get_provider()
                    hook = provider.generate_hook(code, cat)
                    out = os.path.join(config.FRIDA_SCRIPTS_PATH, "ai_generated.js")
                    if not os.path.exists(config.FRIDA_SCRIPTS_PATH):
                        os.makedirs(config.FRIDA_SCRIPTS_PATH)
                    with open(out, "w") as f: f.write(hook)
                    print()
                    print(f"[+] Saved to {out}".center(width))
                    print(hook)
                except Exception as e: print(f"[-] AI Error: {e}".center(width))
            else: print("[-] File not found.".center(width))

        elif choice == '4':
            pkg = c_input("Enter Package Name")
            dumper = ADBDumper(pkg)
            results = dumper.pull_data()
            print()
            print("[+] Exfiltration Results:".center(width))
            for r in results:
                status = "V" if r['status'] == 'pulled' else "X"
                print(f"{status} {r['target']}".center(width))

        elif choice == '5':
            scripts = FridaOrchestrator(None).list_scripts()
            print()
            print("[+] Script Library:".center(width))
            print()
            if not scripts: print("(No scripts found in frida-scripts/)".center(width))
            for s in scripts:
                print(f"- {s}".center(width))

        elif choice == '6':
            print("[*] Feature coming soon: Select/Change ADB Device".center(width))

        elif choice == '0':
            print("Exiting APex...".center(width))
            break
        
        print()
        c_input("Press Enter to return to menu", show_indicator=False)

def main():
    parser = argparse.ArgumentParser(description="🛡️  APex CLI", add_help=False)
    parser.add_argument('-h', '--help', action='help')
    subparsers = parser.add_subparsers(dest="command")
    
    subparsers.add_parser("scan").add_argument("apk_path")
    subparsers.add_parser("inject").add_argument("package_name")
    subparsers.add_parser("list-scripts")
    subparsers.add_parser("exfiltrate").add_argument("package_name")
    subparsers.add_parser("generate-hook").add_argument("smali_file")

    if len(sys.argv) == 1:
        interactive_menu()
        return

    args = parser.parse_args()
    if args.command == "scan":
        scanner = APKScanner(args.apk_path)
        if scanner.decompile(): print(json.dumps(scanner.find_security_logic(), indent=2))
    elif args.command == "list-scripts":
        for s in FridaOrchestrator(None).list_scripts(): print(f"  - {s}")
    elif args.command == "inject":
        FridaOrchestrator(args.package_name).attach_and_inject(args.script_name)

if __name__ == "__main__":
    main()
