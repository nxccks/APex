import argparse
import sys
import json
import os
from backend.core.scanner import APKScanner
from backend.core.dynamic import FridaOrchestrator
from backend.core.dumper import ADBDumper
from backend.ai.provider import AIProviderFactory
from backend.config import config

def main():
    parser = argparse.ArgumentParser(
        description="APex: AI-Powered APK Explorer & Exfiltrator CLI",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # 1. Scan
    scan_parser = subparsers.add_parser("scan", help="Decompile and scan an APK for security logic (SAST)")
    scan_parser.add_argument("apk_path", help="Path to the APK file to analyze")

    # 2. List Scripts
    subparsers.add_parser("list-scripts", help="List available Frida scripts in your local directory")

    # 3. Inject
    inject_parser = subparsers.add_parser("inject", help="Inject a Frida script into a running app (DAST)")
    inject_parser.add_argument("package_name", help="Target app package name (e.g., com.example.app)")
    inject_parser.add_argument("script_name", help="Name of the script to inject (must be in frida-scripts/)")

    # 4. Generate AI Hook
    hook_parser = subparsers.add_parser("generate-hook", help="Ask AI to generate a custom Frida bypass hook")
    hook_parser.add_argument("smali_file", help="Path to a text file containing the target Smali code")
    hook_parser.add_argument("--category", default="ssl_pinning", help="Bypass category (default: ssl_pinning)")

    # 5. Exfiltrate
    exfil_parser = subparsers.add_parser("exfiltrate", help="Pull sensitive data (.db, .so, .xml) from the device")
    exfil_parser.add_argument("package_name", help="Target app package name")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # --- Command Execution ---

    if args.command == "scan":
        if not os.path.exists(args.apk_path):
            print(f"[-] Error: File not found at {args.apk_path}")
            sys.exit(1)
            
        print(f"[*] Starting APex Scanner on {args.apk_path}...")
        scanner = APKScanner(args.apk_path)
        
        if scanner.decompile():
            print("[*] Decompilation successful. Hunting for security logic...")
            findings = scanner.find_security_logic()
            print(f"\n[+] Scan Complete! Found {len(findings)} points of interest:\n")
            print(json.dumps(findings, indent=2))
        else:
            print("[-] Decompilation failed. Ensure Java is installed and working.")
            sys.exit(1)

    elif args.command == "list-scripts":
        orchestrator = FridaOrchestrator(None)
        scripts = orchestrator.list_scripts()
        print("\n[+] Available Frida Scripts:")
        if not scripts:
            print("  (No scripts found in frida-scripts/)")
        for s in scripts:
            print(f"  - {s}")
        print()

    elif args.command == "inject":
        print(f"[*] Attaching to {args.package_name} and injecting {args.script_name}...")
        orchestrator = FridaOrchestrator(args.package_name)
        if orchestrator.attach_and_inject(args.script_name):
            print(f"[+] Successfully injected {args.script_name}! (Press Ctrl+C to exit if persistent)")
        else:
            print(f"[-] Failed to inject script. Is frida-server running and the app open?")
            sys.exit(1)

    elif args.command == "generate-hook":
        if not os.path.exists(args.smali_file):
            print(f"[-] Error: Smali text file not found at {args.smali_file}")
            sys.exit(1)
            
        with open(args.smali_file, 'r') as f:
            smali_code = f.read()
            
        print(f"[*] Analyzing Smali code with AI ({config.AI_PROVIDER})...")
        try:
            provider = AIProviderFactory.get_provider()
            hook = provider.generate_hook(smali_code, args.category)
            
            # Ensure script dir exists
            if not os.path.exists(config.FRIDA_SCRIPTS_PATH):
                os.makedirs(config.FRIDA_SCRIPTS_PATH)
                
            out_path = os.path.join(config.FRIDA_SCRIPTS_PATH, "ai_generated.js")
            with open(out_path, "w") as f:
                f.write(hook)
                
            print(f"[+] Success! Hook generated and saved to: {out_path}\n")
            print("--- Generated Hook ---")
            print(hook)
            print("----------------------")
        except Exception as e:
            print(f"[-] AI Generation failed: {e}")

    elif args.command == "exfiltrate":
        print(f"[*] Initiating ADB data exfiltration for {args.package_name}...")
        dumper = ADBDumper(args.package_name)
        results = dumper.pull_data()
        
        print("\n[+] Exfiltration Results:")
        for r in results:
            status = "✅" if r['status'] == 'pulled' else "❌"
            print(f"  {status} {r['target']} -> {r.get('status')}")
        print(f"\n[*] Check the './downloads/{args.package_name}' directory for your loot.")

if __name__ == "__main__":
    main()
