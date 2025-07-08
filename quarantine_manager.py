import os
import time
import json
import sqlite3
import hashlib
import secrets
import logging
import base64
from pathlib import Path
from datetime import datetime
from threading import Lock
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class QuarantineManager:
    """Manage quarantined files and threats"""
    
    def __init__(self, file_scanner, quarantine_dir="quarantine"):
        self.file_scanner = file_scanner
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(exist_ok=True)
        
        self.quarantine_db = self.quarantine_dir / "quarantine.db"
        self.db_lock = Lock()  # Thread safety lock
        self.init_database()
    
    def init_database(self):
        """Initialize quarantine database"""
        try:
            with self.db_lock:
                conn = sqlite3.connect(str(self.quarantine_db), timeout=10)
                cursor = conn.cursor()
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS quarantined_files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        original_path TEXT NOT NULL,
                        quarantine_path TEXT NOT NULL,
                        file_hash TEXT NOT NULL,
                        quarantine_date TEXT NOT NULL,
                        threat_type TEXT,
                        threat_level INTEGER,
                        file_size INTEGER,
                        restoration_info TEXT
                    )
                ''')
                
                conn.commit()
                conn.close()
                
        except Exception as e:
            logging.error(f"Error initializing quarantine database: {e}")
    
    def _generate_encryption_key(self):
        """Generate encryption key for quarantined files"""
        return secrets.token_bytes(32)
    
    def quarantine_file(self, file_path, threat_info):
        """Quarantine a malicious file"""
        try:
            if not os.path.exists(file_path):
                return False, "File not found"
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            
            # Generate quarantine filename
            quarantine_filename = f"{file_hash}_{int(time.time())}.quar"
            quarantine_path = self.quarantine_dir / quarantine_filename
            
            # Generate unique encryption key for this file
            file_key = self._generate_encryption_key()
            
            # Encrypt and move file
            if self._encrypt_and_move_file(file_path, quarantine_path, file_key):
                # Verify quarantine file exists before proceeding
                if not os.path.exists(quarantine_path):
                    return False, "Encryption failed - quarantine file missing"
                
                # Store quarantine information with file key
                original_permissions = oct(os.stat(file_path).st_mode)
                restoration_info = {
                    'original_permissions': original_permissions,
                    'file_key': base64.b64encode(file_key).decode()
                }
                
                self._store_quarantine_info(
                    file_path, str(quarantine_path), file_hash,
                    threat_info.get('threat_type', 'unknown'),
                    threat_info.get('threat_level', 0),
                    os.path.getsize(file_path),
                    json.dumps(restoration_info)
                )
                
                # Only remove original after successful encryption and DB storage
                os.remove(file_path)
                
                logging.info(f"File quarantined: {file_path} -> {quarantine_path}")
                return True, "File quarantined successfully"
            else:
                return False, "Failed to encrypt and move file"
                
        except Exception as e:
            logging.error(f"Error quarantining file {file_path}: {e}")
            return False, str(e)
    
    def _encrypt_and_move_file(self, source_path, dest_path, key):
        """Encrypt file using AES-GCM and move to quarantine"""
        try:
            cipher = AES.new(key, AES.MODE_GCM)
            
            with open(source_path, 'rb') as f:
                data = f.read()

            ciphertext, tag = cipher.encrypt_and_digest(pad(data, AES.block_size))

            with open(dest_path, 'wb') as f:
                f.write(b'QUAR')                  # Header
                f.write(len(key).to_bytes(4, 'little'))
                f.write(cipher.nonce)             # GCM uses nonce instead of IV
                f.write(tag)                      # Authentication tag
                f.write(ciphertext)

            return True
        except Exception as e:
            logging.error(f"Error encrypting file: {e}")
            return False
        
    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logging.error(f"Failed to calculate hash for {file_path}: {e}")
            return ""
        
    def _store_quarantine_info(self, original_path, quarantine_path, file_hash, 
                              threat_type, threat_level, file_size, restoration_info):
        """Store quarantine information in database"""
        try:
            with self.db_lock:
                conn = sqlite3.connect(str(self.quarantine_db), timeout=10)
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO quarantined_files 
                    (original_path, quarantine_path, file_hash, quarantine_date, 
                     threat_type, threat_level, file_size, restoration_info)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    original_path, quarantine_path, file_hash,
                    datetime.now().isoformat(), threat_type, threat_level,
                    file_size, restoration_info
                ))
                
                conn.commit()
                conn.close()
                
        except Exception as e:
            logging.error(f"Error storing quarantine info: {e}")
    
    def restore_file(self, quarantine_id):
        """Restore a quarantined file"""
        try:
            with self.db_lock:
                with sqlite3.connect(str(self.quarantine_db), timeout=10) as conn:
                    cursor = conn.cursor()

                    cursor.execute('''
                        SELECT original_path, quarantine_path, restoration_info
                        FROM quarantined_files WHERE id = ?
                    ''', (quarantine_id,))
                    
                    result = cursor.fetchone()
                    if not result:
                        return False, "Quarantined file not found"
                    
                    original_path, quarantine_path, restoration_info = result

                    if not os.path.exists(quarantine_path):
                        return False, f"Quarantine file not found: {quarantine_path}"

                    # Load restoration info and get file key
                    info = json.loads(restoration_info)
                    file_key = base64.b64decode(info["file_key"])

                    if self._decrypt_and_restore_file(quarantine_path, original_path, file_key):
                        # Verify hash integrity
                        restored_hash = self._calculate_file_hash(original_path)
                        cursor.execute('SELECT file_hash FROM quarantined_files WHERE id = ?', (quarantine_id,))
                        expected_hash = cursor.fetchone()[0]
                        if restored_hash != expected_hash:
                            logging.warning("Restored file hash does not match original.")
                            return False, "File integrity check failed"

                        # Restore file permissions if available and file exists
                        if os.path.exists(original_path) and "original_permissions" in info:
                            try:
                                os.chmod(original_path, int(info["original_permissions"], 8))
                            except Exception as e:
                                logging.warning(f"Could not restore file permissions: {e}")

                        # Delete DB entry and quarantine file
                        cursor.execute('DELETE FROM quarantined_files WHERE id = ?', (quarantine_id,))
                        conn.commit()

                        if os.path.exists(quarantine_path):
                            os.remove(quarantine_path)

                        logging.info(f"File restored: {original_path}")
                        return True, "File restored successfully"
                    else:
                        return False, "Failed to decrypt and restore file"

        except Exception as e:
            logging.error(f"Error restoring file: {e}")
            return False, str(e)

    def _decrypt_and_restore_file(self, quarantine_path, restore_path, key):
        """Decrypt file using AES-GCM and restore to original location"""
        try:
            with open(quarantine_path, 'rb') as f:
                header = f.read(4)
                if header != b'QUAR':
                    return False

                key_len = int.from_bytes(f.read(4), 'little')
                if key_len != len(key):
                    return False

                nonce = f.read(16)  # GCM uses 16-byte nonce
                tag = f.read(16)    # GCM tag is 16 bytes
                ciphertext = f.read()

            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            try:
                decrypted_data = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)
            except ValueError as e:
                logging.error(f"Decryption failed: {e}")
                return False

            Path(restore_path).parent.mkdir(parents=True, exist_ok=True)

            with open(restore_path, 'wb') as f:
                f.write(decrypted_data)

            return True

        except Exception as e:
            logging.error(f"Error decrypting file: {e}")
            return False
    
    # ... (rest of the methods remain unchanged)

    
    def list_quarantined_files(self):
        """List all quarantined files"""
        try:
            conn = sqlite3.connect(str(self.quarantine_db))
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, original_path, file_hash, quarantine_date,
                       threat_type, threat_level, file_size
                FROM quarantined_files
                ORDER BY quarantine_date DESC
            ''')
            
            results = cursor.fetchall()
            conn.close()
            
            quarantined_files = []
            for result in results:
                quarantined_files.append({
                    'id': result[0],
                    'original_path': result[1],
                    'file_hash': result[2],
                    'quarantine_date': result[3],
                    'threat_type': result[4],
                    'threat_level': result[5],
                    'file_size': result[6]
                })
            
            return quarantined_files
            
        except Exception as e:
            logging.error(f"Error listing quarantined files: {e}")
            return []
    
    def get_quarantine_stats(self):
        """Get quarantine statistics"""
        try:
            conn = sqlite3.connect(str(self.quarantine_db))
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM quarantined_files')
            total_files = cursor.fetchone()[0]
            
            cursor.execute('SELECT SUM(file_size) FROM quarantined_files')
            total_size = cursor.fetchone()[0] or 0
            
            cursor.execute('''
                SELECT threat_type, COUNT(*) 
                FROM quarantined_files 
                GROUP BY threat_type
            ''')
            threat_breakdown = dict(cursor.fetchall())
            
            conn.close()
            
            return {
                'total_files': total_files,
                'total_size': total_size,
                'threat_breakdown': threat_breakdown
            }
            
        except Exception as e:
            logging.error(f"Error getting quarantine stats: {e}")
            return {'total_files': 0, 'total_size': 0, 'threat_breakdown': {}}
