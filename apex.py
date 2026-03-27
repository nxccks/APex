#!/usr/bin/env python3
import argparse
import sys
import json
import os
import shutil
from backend.core.scanner import APKScanner
from backend.core.dynamic import FridaOrchestrator
from backend.core.dumper import ADBDumper
from backend.ai.provider import AIProviderFactory
from backend.config import config

# --- UI Styling ---
def clr(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

def print_header():
    width = shutil.get_terminal_size().columns
    print("\n" + clr("=" * 60, "96").center(width))
    print(clr("🛡️  APEX: AI-Powered APK Explorer & Exfiltrator", "96;1").center(width))
    print(clr("=" * 60, "96").center(width) + "\n")

def interactive_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print_header()
        width = shutil.get_terminal_size().columns
        
        print(clr("[ MAIN MENU ]", "93").center(width))
        print("1. 🔍 Scan APK (Static Analysis)".center(width))
        print("2. 💉 Inject Frida Script (Dynamic)".center(width))
        print("3. 🤖 Generate AI Bypass Hook".center(width))
        print("4. 💾 Exfiltrate App Data (ADB)".center(width))
        print("5. 📜 List Local Scripts".center(width))
        print("0. 🚪 Exit".center(width))
        print("\n" + clr("-" * 20, "90").center(width))
        
        choice = input(clr("\nSelect an option > ", "92")).strip()

        if choice == '1':
            path = input(clr("Enter APK path: ", "94")).strip()
            if os.path.exists(path):
                scanner = APKScanner(path)
                if scanner.decompile():
                    findings = scanner.find_security_logic()
                    print(clr("\n[+] Findings:", "92"))
                    print(json.dumps(findings, indent=2))
                else: print(clr("[-] Decompilation failed.", "91"))
            else: print(clr("[-] File not found.", "91"))

        elif choice == '2':
            pkg = input(clr("Enter Package Name: ", "94")).strip()
            script = input(clr("Enter Script Name (e.g. universal.js): ", "94")).strip()
            orch = FridaOrchestrator(pkg)
            if orch.attach_and_inject(script): print(clr("[+] Injection Success!", "92"))
            else: print(clr("[-] Injection Failed.", "91"))

        elif choice == '3':
            file_path = input(clr("Enter path to Smali snippet file: ", "94")).strip()
            if os.path.exists(file_path):
                with open(file_path, 'r') as f: code = f.read()
                cat = input(clr("Category (default: ssl_pinning): ", "94")).strip() or "ssl_pinning"
                try:
                    provider = AIProviderFactory.get_provider()
                    hook = provider.generate_hook(code, cat)
                    out = os.path.join(config.FRIDA_SCRIPTS_PATH, "ai_generated.js")
                    with open(out, "w") as f: f.write(hook)
                    print(clr(f"\n[+] Saved to {out}\n", "92") + clr(hook, "93"))
                except Exception as e: print(clr(f"[-] AI Error: {e}", "91"))
            else: print(clr("[-] File not found.", "91"))

        elif choice == '4':
            pkg = input(clr("Enter Package Name: ", "94")).strip()
            dumper = ADBDumper(pkg)
            results = dumper.pull_data()
            for r in results:
                status = "✅" if r['status'] == 'pulled' else "❌"
                print(f"  {status} {r['target']}")

        elif choice == '5':
            scripts = FridaOrchestrator(None).list_scripts()
            print(clr("\n[+] Script Library:", "92"))
            for s in scripts: print(f"  - {s}")

        elif choice == '0':
            print(clr("Exiting APex...", "96"))
            break
        
        input(clr("\nPress Enter to return to menu...", "90"))

def main():
    parser = argparse.ArgumentParser(description="🛡️  APex CLI", add_help=False)
    parser.add_argument('-h', '--help', action='help')
    subparsers = parser.add_subparsers(dest="command")
    
    # Define subparsers for CLI (keeping argument support)
    scan_p = subparsers.add_parser("scan")
    scan_p.add_argument("apk_path")
    
    inject_p = subparsers.add_parser("inject")
    inject_p.add_argument("package_name")
    inject_p.add_argument("script_name")
    
    hook_p = subparsers.add_parser("generate-hook")
    hook_p.add_argument("smali_file")
    
    exfil_p = subparsers.add_parser("exfiltrate")
    exfil_p.add_argument("package_name")
    
    subparsers.add_parser("list-scripts")

    # If no arguments, enter INTERACTIVE MODE
    if len(sys.argv) == 1:
        interactive_menu()
        return

    args = parser.parse_args()

    # (Logic for CLI arguments - similar to interactive blocks above)
    if args.command == "scan":
        scanner = APKScanner(args.apk_path)
        if scanner.decompile(): print(json.dumps(scanner.find_security_logic(), indent=2))
    elif args.command == "list-scripts":
        for s in FridaOrchestrator(None).list_scripts(): print(f"  - {s}")
    elif args.command == "inject":
        FridaOrchestrator(args.package_name).attach_and_inject(args.script_name)
    elif args.command == "exfiltrate":
        ADBDumper(args.package_name).pull_data()

if __name__ == "__main__":
    main()
