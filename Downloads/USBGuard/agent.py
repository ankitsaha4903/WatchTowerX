# agent.py

import time
import getpass
import os
import threading
import wmi
import pythoncom
import re
import winsound
from PIL import Image, ImageDraw
import pystray
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from config import SCAN_INTERVAL_SECONDS
from db import (
    init_db,
    upsert_device,
    update_device_status,
    log_event,
    get_policies,
    get_device_by_mount,
    get_sensitive_keywords,
    get_sensitive_regex,
)
from notifier import send_alert


# --------- Helper Functions --------- #

def get_device_serial(mount_point: str) -> str:
    """
    Get the Volume Serial Number using win32api (more reliable) or WMI.
    mount_point is like 'E:\\'
    """
    # Method 1: win32api GetVolumeInformation
    try:
        import win32api
        # GetVolumeInformation returns: (vol_name, vol_serial, max_comp_len, flags, fs_name)
        vol_info = win32api.GetVolumeInformation(mount_point)
        serial_int = vol_info[1]
        # Convert to standard hex format (e.g. 1234-ABCD)
        serial_hex = f"{serial_int & 0xFFFFFFFF:08X}"
        return f"{serial_hex[:4]}-{serial_hex[4:]}"
    except Exception as e:
        print(f"win32api serial error for {mount_point}: {e}")

    # Method 2: WMI Fallback
    try:
        # WMI needs to be initialized in the thread
        pythoncom.CoInitialize()
        c = wmi.WMI()
        drive_letter = mount_point.rstrip("\\")  # e.g. 'E:'
        
        # Query LogicalDisk where DeviceID matches the drive letter
        for disk in c.Win32_LogicalDisk(DeviceID=drive_letter):
            return disk.VolumeSerialNumber or "UnknownSerial"
    except Exception as e:
        print(f"WMI serial error for {mount_point}: {e}")
        
    # Method 3: Fallback to a unique hash of mount point + time if absolutely necessary
    # But we want to avoid this if possible to allow re-plugging.
    # If we return UnknownSerial, the agent uses mount_point as ID.
    return "UnknownSerial"


def create_tray_icon(agent):
    """
    Create a system tray icon.
    """
    # Create a simple icon image
    width = 64
    height = 64
    color1 = "blue"
    color2 = "white"
    image = Image.new('RGB', (width, height), color1)
    dc = ImageDraw.Draw(image)
    dc.rectangle((width // 2, 0, width, height // 2), fill=color2)
    dc.rectangle((0, height // 2, width // 2, height), fill=color2)

    def on_quit(icon, item):
        icon.stop()
        agent.stop()

    menu = pystray.Menu(
        pystray.MenuItem('USB Guard Running', lambda: None, enabled=False),
        pystray.MenuItem('Quit', on_quit)
    )

    icon = pystray.Icon("USB Guard", image, "USB Guard Agent", menu)
    return icon


# --------- File System Event Handler --------- #

class USBFileEventHandler(FileSystemEventHandler):
    def __init__(self, mount_point: str, username: str, agent_ref):
        super().__init__()
        self.mount_point = mount_point
        self.username = username
        self.agent_ref = agent_ref

    def scan_file_content(self, filepath: str):
        """
        Scan file for sensitive keywords and regex patterns.
        """
        keywords = get_sensitive_keywords()
        regex_patterns = get_sensitive_regex()
        
        # Log Start of Scan
        log_event("INFO", "scan_start", f"Scanning: {filepath}", username=self.username, mount_point=self.mount_point)
        
        if not keywords and not regex_patterns:
            return

        try:
            # Try reading as text
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Check Keywords
            for kw_obj in keywords:
                kw = kw_obj['keyword']
                if kw in content:
                    self.handle_dlp_violation(filepath, f"Keyword: {kw}")
                    return

            # Check Regex
            for r_obj in regex_patterns:
                pattern = r_obj['pattern']
                description = r_obj['description']
                try:
                    if re.search(pattern, content):
                        self.handle_dlp_violation(filepath, f"Regex: {description} ({pattern})")
                        return
                except re.error as e:
                    print(f"Invalid regex pattern {pattern}: {e}")
            
            # If we reach here, file is safe
            log_event("INFO", "scan_safe", f"Clean: {filepath}", username=self.username, mount_point=self.mount_point)

        except Exception as e:
            print(f"Error scanning file {filepath}: {e}")
            log_event("WARN", "scan_error", f"Error scanning {filepath}: {e}", username=self.username, mount_point=self.mount_point)

    def handle_dlp_violation(self, filepath: str, reason: str):
        """
        Handle DLP violation: Delete file, Log, Alert, Beep, Block Device.
        """
        try:
            # 1. Beep Sound
            winsound.Beep(1000, 1000) # 1000Hz for 1 sec
            
            # 2. Delete File
            os.remove(filepath)
            msg = f"DLP VIOLATION: File '{filepath}' deleted. Reason: {reason}"
            print(f"[DLP] {msg}")
            
            # 3. Log
            log_event(
                "CRITICAL",
                "dlp_violation",
                msg,
                username=self.username,
                mount_point=self.mount_point
            )
            
            # 4. Alert
            send_alert("USBGuard: DLP Violation Detected", msg)
            
            # 5. Auto-Block Device
            update_device_status(self.mount_point, "blocked", "auto_blocked_malicious")
            log_event(
                "CRITICAL",
                "usb_blocked_malicious",
                f"USB at {self.mount_point} auto-blocked due to malicious content.",
                username=self.username,
                mount_point=self.mount_point
            )
            
            # Stop monitoring this device
            self.agent_ref.stop_file_monitor(self.mount_point)
            
        except Exception as e:
            print(f"Failed to handle DLP violation for {filepath}: {e}")

    def on_created(self, event):
        if not event.is_directory:
            msg = f"New file created on USB {self.mount_point}: {event.src_path}"
            log_event("INFO", "file_created_usb", msg, username=self.username, mount_point=self.mount_point)
            self.scan_file_content(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            msg = f"File modified on USB {self.mount_point}: {event.src_path}"
            log_event("INFO", "file_modified_usb", msg, username=self.username, mount_point=self.mount_point)
            self.scan_file_content(event.src_path)


# ---------- USB Monitoring Agent ----------- #

class USBGuardAgent:
    def __init__(self):
        self.current_usb_mounts = set()
        self.observers = {}  # mount_point -> Observer
        self.username = getpass.getuser()
        self.running = True
    
    def stop(self):
        self.running = False

    def scan_usb_devices(self):
        """
        Scan for removable drives using psutil.
        """
        removable_mounts = set()
        for part in psutil.disk_partitions(all=False):
            if "removable" in part.opts.lower():
                removable_mounts.add(part.mountpoint)
        return removable_mounts

    def apply_policy_for_new_device(self, mount_point: str):
        policies = get_policies()
        default_action = policies.get("default_usb_action", "block_unknown")

        # Get Reliable Serial Number
        serial = get_device_serial(mount_point)
        device_id = serial if serial != "UnknownSerial" else mount_point
        
        vendor = "UnknownVendor"
        product = "UnknownProduct"

        # Ensure device record exists / is updated
        upsert_device(mount_point, device_id, vendor, product)

        # Check existing device status from DB
        device_row = get_device_by_mount(mount_point)
        existing_status = device_row["status"] if device_row else "pending_approval"

        if existing_status == "allowed":
            update_device_status(mount_point, "allowed", "whitelisted_allowed")
            log_event(
                "INFO",
                "usb_allowed_whitelist",
                f"Whitelisted USB device allowed at {mount_point} (ID: {device_id})",
                username=self.username,
                device_id=device_id,
                mount_point=mount_point
            )
            self.start_file_monitor(mount_point)
            action = "allowed (whitelist)"

        elif existing_status == "blocked":
            update_device_status(mount_point, "blocked", "manually_blocked")
            log_event(
                "WARN",
                "usb_blocked_manual",
                f"Manually blocked USB device at {mount_point} (ID: {device_id})",
                username=self.username,
                device_id=device_id,
                mount_point=mount_point
            )
            self.alert_block(mount_point, device_id)
            action = "blocked (manual)"
            
        elif existing_status == "pending_approval":
            # Do NOT start monitor. Wait for user.
            log_event(
                "WARN",
                "usb_pending",
                f"New USB device at {mount_point} waiting for approval (ID: {device_id})",
                username=self.username,
                device_id=device_id,
                mount_point=mount_point
            )
            action = "pending approval"

        else:
            # Fallback for other statuses
            action = f"unknown status ({existing_status})"

        print(f"[Agent] New USB {mount_point} (ID: {device_id}) -> {action}")

    def check_pending_devices(self):
        """
        Check if any currently connected devices have been approved/blocked.
        """
        for mount_point in list(self.current_usb_mounts):
            # Check if we are already monitoring
            if mount_point in self.observers:
                continue
                
            device_row = get_device_by_mount(mount_point)
            if not device_row:
                continue
                
            status = device_row["status"]
            
            if status == "allowed":
                print(f"[Agent] Device at {mount_point} approved! Starting monitor.")
                log_event("INFO", "usb_approved", f"Device at {mount_point} approved by user.", username=self.username, mount_point=mount_point)
                self.start_file_monitor(mount_point)
                
            elif status == "blocked":
                # Ensure we log it once if it transitioned from pending -> blocked
                # But we don't need to do anything else since we aren't monitoring
                pass

    def alert_block(self, mount_point: str, device_id: str):
        policies = get_policies()
        if policies.get("alert_on_block") == "true":
            subject = f"USBGuard: Blocked USB at {mount_point}"
            body = (
                f"User {self.username} tried to use USB device {device_id} at {mount_point} "
                f"which was blocked according to current policy."
            )
            send_alert(subject, body)

    def start_file_monitor(self, mount_point: str):
        if mount_point in self.observers:
            return
        event_handler = USBFileEventHandler(mount_point, self.username, self)
        observer = Observer()
        observer.schedule(event_handler, mount_point, recursive=True)
        observer.start()
        self.observers[mount_point] = observer
        print(f"[Agent] Started file monitor on {mount_point}")

    def stop_file_monitor(self, mount_point: str):
        observer = self.observers.get(mount_point)
        if observer:
            observer.stop()
            observer.join()
            del self.observers[mount_point]
            print(f"[Agent] Stopped file monitor on {mount_point}")

    def run_loop(self):
        print("[Agent] Initializing database...")
        init_db()
        print("[Agent] USBGuard Agent started.")
        try:
            while self.running:
                new_mounts = self.scan_usb_devices()

                # Detect newly connected devices
                for m in new_mounts - self.current_usb_mounts:
                    log_event("INFO", "usb_connected", f"USB connected at {m}", username=self.username, mount_point=m)
                    self.apply_policy_for_new_device(m)

                # Detect removed devices
                for m in self.current_usb_mounts - new_mounts:
                    log_event("INFO", "usb_disconnected", f"USB removed from {m}", username=self.username, mount_point=m)
                    self.stop_file_monitor(m)

                self.current_usb_mounts = new_mounts
                
                # Check for status updates on pending devices
                self.check_pending_devices()
                
                time.sleep(SCAN_INTERVAL_SECONDS)
        except Exception as e:
            print(f"[Agent] Error in run loop: {e}")
        finally:
            for m in list(self.observers.keys()):
                self.stop_file_monitor(m)
            print("[Agent] Exited cleanly.")


if __name__ == "__main__":
    agent = USBGuardAgent()
    
    # Run agent loop in a separate thread
    agent_thread = threading.Thread(target=agent.run_loop, daemon=True)
    agent_thread.start()
    
    # Run system tray icon on the main thread
    icon = create_tray_icon(agent)
    icon.run()
