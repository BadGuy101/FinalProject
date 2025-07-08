
import os
import time
import logging
import psutil
from queue import Queue
from threading import Thread
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from utils.notifications import notify_user
from utils.crypto import hash_file
from config.settings import WATCH_PATH, ALLOWED_EXTENSIONS

scan_queue = Queue()
scanned_hashes = deque(maxlen=10000)

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
MODIFICATION_WAIT = 2  # seconds

def kill_matching_processes(file_path):
    for proc in psutil.process_iter(['pid', 'exe']):
        try:
            if proc.info['exe'] and os.path.samefile(proc.info['exe'], file_path):
                logging.warning(f"Killing process PID {proc.pid} using {file_path}")
                proc.terminate()
        except (psutil.AccessDenied, psutil.NoSuchProcess, FileNotFoundError):
            continue

class FileWatcher(FileSystemEventHandler):
    def __init__(self, scanner, quarantine_manager):
        self.scanner = scanner
        self.quarantine_manager = quarantine_manager

    def is_valid_file(self, path):
        return path.lower().endswith(tuple(ALLOWED_EXTENSIONS))

    def queue_file(self, path):
        if not self.is_valid_file(path):
            return
        try:
            if os.path.getsize(path) > MAX_FILE_SIZE:
                logging.info(f"Skipped large file: {path}")
                return
            if time.time() - os.path.getmtime(path) < MODIFICATION_WAIT:
                time.sleep(1)
        except Exception as e:
            logging.warning(f"Could not stat file {path}: {e}")
            return
        scan_queue.put(path)

    def on_created(self, event):
        if not event.is_directory:
            self.queue_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.queue_file(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            logging.info(f"File deleted: {event.src_path}")

def scan_worker(scanner, quarantine_manager):
    while True:
        file_path = scan_queue.get()
        try:
            if not os.path.exists(file_path):
                logging.warning(f"Skipped missing file: {file_path}")
                continue

            for _ in range(3):
                try:
                    with open(file_path, "rb"):
                        break
                except PermissionError:
                    time.sleep(0.5)
            else:
                logging.warning(f"File remained locked: {file_path}")
                continue

            file_hash = hash_file(file_path)
            if not file_hash:
                logging.warning(f"Skipping file with invalid hash: {file_path}")
                continue

            if file_hash in scanned_hashes:
                logging.info(f"Skipped previously scanned file: {file_path}")
                continue

            scanned_hashes.append(file_hash)

            result = scanner.scan_file(file_path)
            if result.get("is_malicious"):
                kill_matching_processes(file_path)
                threat_level = result.get("threat_level", "unknown")
                detections = result.get("detections", [])
                logging.warning(f"Threat detected in {file_path}")
                logging.info(f"Threat level: {threat_level}, Detections: {detections}")
                notify_user("Threat Detected", f"Malicious File - {os.path.basename(file_path)}")
                quarantine_manager.quarantine_file(file_path, threat_info=result)

        except Exception as e:
            logging.error(f"[Error scanning {file_path}: {str(e)}")
        finally:
            scan_queue.task_done()

def start_watching(scanner, quarantine_manager, shutdown_event):
    if not os.path.exists(WATCH_PATH):
        os.makedirs(WATCH_PATH)
    observer = Observer()
    handler = FileWatcher(scanner, quarantine_manager)
    observer.schedule(handler, path=WATCH_PATH, recursive=True)
    observer.start()
    logging.info(f" Watching {WATCH_PATH} for new/changed files...")

    # Start file scanning worker
    Thread(target=scan_worker, args=(scanner, quarantine_manager), daemon=True).start()

    try:
        while not shutdown_event.is_set():  # ✅ graceful shutdown
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("File watcher received keyboard interrupt.")
        shutdown_event.set()

    observer.stop()
    observer.join()
    logging.info("📁 File watcher stopped.")