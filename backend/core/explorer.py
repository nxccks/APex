import os
import sqlite3
import xml.dom.minidom

class LootExplorer:
    def __init__(self, downloads_path):
        self.downloads_path = downloads_path

    def list_sessions(self):
        """Lists all package sessions in the downloads folder"""
        if not os.path.exists(self.downloads_path):
            return []
        return [d for d in os.listdir(self.downloads_path) if os.path.isdir(os.path.join(self.downloads_path, d))]

    def list_files(self, package_name):
        """Lists all files exfiltrated for a specific package"""
        session_path = os.path.join(self.downloads_path, package_name)
        file_list = []
        for root, _, files in os.walk(session_path):
            for f in files:
                file_list.append(os.path.relpath(os.path.join(root, f), session_path))
        return sorted(file_list)

    def explore_db(self, package_name, db_rel_path):
        """Dumps tables and rows from a selected SQLite database"""
        db_path = os.path.join(self.downloads_path, package_name, db_rel_path)
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Get tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [t[0] for t in cursor.fetchall()]
            
            results = {"tables": {}}
            for table in tables:
                cursor.execute(f"SELECT * FROM {table} LIMIT 10")
                columns = [description[0] for description in cursor.description]
                rows = cursor.fetchall()
                results["tables"][table] = {"columns": columns, "rows": rows}
            
            conn.close()
            return results
        except Exception as e:
            return {"error": str(e)}

    def view_xml(self, package_name, xml_rel_path):
        """Pretty-prints an exfiltrated XML file"""
        xml_path = os.path.join(self.downloads_path, package_name, xml_rel_path)
        try:
            with open(xml_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                # Basic pretty print if it's valid XML
                try:
                    dom = xml.dom.minidom.parseString(content)
                    return dom.toprettyxml()
                except:
                    return content
        except Exception as e:
            return f"Error reading file: {e}"
