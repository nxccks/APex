import os
import sqlite3
import xml.dom.minidom
import json
import binascii

class LootExplorer:
    def __init__(self, downloads_path):
        self.downloads_path = downloads_path

    def list_sessions(self):
        """Lists all package sessions in the downloads folder"""
        if not os.path.exists(self.downloads_path):
            os.makedirs(self.downloads_path)
            return []
        return [d for d in os.listdir(self.downloads_path) if os.path.isdir(os.path.join(self.downloads_path, d))]

    def list_files(self, package_name):
        """Lists all files exfiltrated for a specific package recursively"""
        session_path = os.path.join(self.downloads_path, package_name)
        if not os.path.exists(session_path):
            return []
            
        file_list = []
        for root, _, files in os.walk(session_path):
            for f in files:
                rel_path = os.path.relpath(os.path.join(root, f), session_path)
                file_list.append(rel_path)
        return sorted(file_list)

    def is_sqlite(self, file_path):
        """Checks if a file is a valid SQLite database via magic header"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
                return header == b'SQLite format 3\x00'
        except:
            return False

    def is_binary(self, file_path):
        """Heuristic to check if a file is binary"""
        try:
            with open(file_path, 'tr') as f:
                f.read(1024)
                return False
        except:
            return True

    def get_hex_dump(self, file_path, limit=256):
        """Returns a hex dump of the first N bytes of a file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(limit)
                hex_str = binascii.hexlify(data, ' ', 16).decode()
                return hex_str
        except Exception as e:
            return f"Error generating hex dump: {e}"

    def explore_db(self, package_name, db_rel_path):
        """Dumps tables and rows from a selected SQLite database"""
        db_path = os.path.join(self.downloads_path, package_name, db_rel_path)
        if not self.is_sqlite(db_path):
            return {"error": "Not a valid SQLite database file."}

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [t[0] for t in cursor.fetchall()]
            
            results = {"tables": {}}
            for table in tables:
                try:
                    cursor.execute(f"SELECT * FROM \"{table}\" LIMIT 10")
                    columns = [description[0] for description in cursor.description]
                    rows = []
                    for row in cursor.fetchall():
                        # Convert binary blobs to hex strings for display
                        clean_row = [f"hex({binascii.hexlify(item).decode()})" if isinstance(item, bytes) else item for item in row]
                        rows.append(clean_row)
                    results["tables"][table] = {"columns": columns, "rows": rows}
                except: continue
            
            conn.close()
            return results
        except Exception as e:
            return {"error": str(e)}

    def view_file(self, package_name, file_rel_path):
        """Reads a file and returns formatted text or a hex dump if binary"""
        full_path = os.path.join(self.downloads_path, package_name, file_rel_path)
        
        if self.is_binary(full_path):
            return f"[ BINARY FILE DETECTED ]\nFirst 256 bytes (Hex):\n\n" + self.get_hex_dump(full_path)

        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # Try JSON pretty print
                try:
                    data = json.loads(content)
                    return json.dumps(data, indent=4)
                except: pass

                # Try XML pretty print
                try:
                    if content.strip().startswith('<'):
                        dom = xml.dom.minidom.parseString(content)
                        return dom.toprettyxml()
                except: pass

                return content
        except Exception as e:
            return f"Error reading file: {e}"
