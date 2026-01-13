import os
import shutil
from pathlib import Path
from datetime import datetime
import json
import getpass
import requests
import webbrowser
from urllib.parse import urljoin, urlparse, parse_qs
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import threading
import builtins  # For replaceable print function

class OneDriveBackup:
    # File extension constants (shared across all methods)
    DOC_EXTENSIONS = frozenset({'.pdf', '.docx', '.doc', '.txt', '.xlsx', '.xls',
                                '.pptx', '.ppt', '.odt', '.rtf', '.csv'})
    PIC_EXTENSIONS = frozenset({'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff',
                                '.svg', '.webp', '.heic', '.raw'})
    VIDEO_EXTENSIONS = frozenset({'.mov', '.mp4', '.avi', '.mkv', '.wmv', '.flv',
                                  '.m4v', '.mpg', '.mpeg', '.3gp', '.webm'})

    def __init__(self):
        self.onedrive_path = self.find_onedrive_path()
        self.backup_log = []
        self.access_token = None
        self.refresh_token = None
        self.client_id = None
        self.client_secret = None
        self.tenant_id = None
        self.use_api = False
        self.downloaded_files = {}  # Changed to dict to store metadata
        self.progress_file = None
        self.large_file_threshold = 100 * 1024 * 1024  # 100MB
        self.file_metadata = {}  # Store file hashes and sizes for incremental backup
        self.metadata_file = None
        self.max_workers = 3  # Number of parallel downloads
        self.progress_lock = Lock()  # Thread-safe progress updates
        self.verification_failures = []
        self.progress_callback = None  # Optional callback for progress updates
        self.should_stop = False  # Flag to stop backup gracefully
        self.start_download_early = False  # Flag to stop scan and start downloading what we have
        
    def find_onedrive_path(self):
        """Automatically locate OneDrive folder"""
        possible_paths = [
            Path.home() / "OneDrive",
            Path.home() / "OneDrive - Personal",
            Path(os.environ.get('OneDrive', '')),
            Path(os.environ.get('OneDriveConsumer', '')),
            Path(os.environ.get('OneDriveCommercial', ''))
        ]
        
        for path in possible_paths:
            if path.exists() and path.is_dir():
                return path
        
        return None
    
    def send_scan_progress(self, items_scanned, files_matching, size_bytes, to_download_count):
        """Send scanning progress to callback if set"""
        if self.progress_callback:
            self.progress_callback({
                'type': 'scanning',
                'items_scanned': items_scanned,
                'files_found': files_matching,
                'size_bytes': size_bytes,
                'size_formatted': self.format_size(size_bytes),
                'to_download': to_download_count
            })

    def send_folder_progress(self, folder_name, folder_scanned, folder_to_download, depth=1, subfolder_path=None, total_scanned=0, total_to_download=0):
        """Send per-folder scanning progress to callback"""
        if self.progress_callback:
            self.progress_callback({
                'type': 'folder_scanning',
                'folder': folder_name,
                'scanned': folder_scanned,
                'to_download': folder_to_download,
                'depth': depth,
                'subfolder': subfolder_path,  # e.g., "Pictures" when scanning "ALC Clips/Pictures"
                'total_scanned': total_scanned,  # Global items scanned count for stats
                'total_to_download': total_to_download  # Global to-download count for stats
            })
    
    def check_disk_space(self, destination, required_space_bytes):
        """
        Check if destination has enough free space.
        
        Args:
            destination: Path to destination drive
            required_space_bytes: Space needed in bytes
            
        Returns:
            tuple: (has_space: bool, available_bytes: int, required_bytes: int)
        """
        try:
            stat = shutil.disk_usage(destination)
            available = stat.free
            
            # Add 10% buffer for safety
            required_with_buffer = required_space_bytes * 1.1
            
            return (available >= required_with_buffer, available, required_with_buffer)
        except Exception as e:
            builtins.print(f"⚠️  Warning: Could not check disk space: {e}")
            return (True, 0, 0)  # Assume OK if we can't check
    
    def format_size(self, bytes_size):
        """Format bytes into human-readable size"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.2f} PB"
    
    def calculate_file_hash(self, file_path, chunk_size=8192):
        """
        Calculate SHA256 hash of a file.
        
        Args:
            file_path: Path to file
            chunk_size: Size of chunks to read (default 8KB)
            
        Returns:
            str: Hexadecimal hash string
        """
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            builtins.print(f"⚠️  Could not hash {file_path}: {e}")
            return None
    
    def verify_file(self, file_path, expected_size, item_id=None):
        """
        Verify downloaded file integrity.
        
        Args:
            file_path: Path to downloaded file
            expected_size: Expected file size in bytes
            item_id: OneDrive item ID (optional)
            
        Returns:
            bool: True if file is valid, False otherwise
        """
        try:
            if not file_path.exists():
                return False
            
            actual_size = file_path.stat().st_size
            
            # Size verification
            if actual_size != expected_size:
                builtins.print(f"⚠️  Size mismatch: {file_path.name} (expected {expected_size}, got {actual_size})")
                # Remove bad metadata if it exists
                if item_id and item_id in self.file_metadata:
                    with self.progress_lock:
                        del self.file_metadata[item_id]
                return False
            
            # Calculate hash for integrity check
            file_hash = self.calculate_file_hash(file_path)
            if not file_hash:
                builtins.print(f"⚠️  Could not calculate hash for {file_path.name}")
                return False
            
            # Only store metadata if file is valid AND has actual content
            if file_hash and item_id and actual_size > 0:  # <- Added size check
                with self.progress_lock:
                    self.file_metadata[item_id] = {
                        'size': actual_size,
                        'hash': file_hash,
                        'path': str(file_path),
                        'modified': datetime.now().isoformat()
                    }
            elif actual_size == 0:
                builtins.print(f"⚠️  Skipping metadata for 0-byte file: {file_path.name}")
            
            return True
            
        except Exception as e:
            builtins.print(f"⚠️  Verification error for {file_path}: {e}")
            # Remove bad metadata if it exists
            if item_id and item_id in self.file_metadata:
                with self.progress_lock:
                    del self.file_metadata[item_id]
            return False
    
    def should_download_file(self, item_id, file_size, file_path):
        """
        Determine if file needs to be downloaded (incremental backup logic).
        
        Args:
            item_id: OneDrive item ID
            file_size: Size of file in OneDrive
            file_path: Local destination path
            
        Returns:
            bool: True if file should be downloaded, False if can skip
        """
        # If file doesn't exist locally, must download
        if not file_path.exists():
            return True
        
        # If we have no metadata, check if file size matches (trust the file on disk)
        if item_id not in self.file_metadata:
            local_size = file_path.stat().st_size
            
            # If size matches, trust the file and skip download
            if local_size == file_size and local_size > 0:
                builtins.print(f"  ✓ File exists with correct size, skipping: {file_path.name}")
                return False  # Skip - file is good!
            else:
                # Size mismatch or 0-byte file - need to download
                builtins.print(f"  File size mismatch ({local_size} vs {file_size}), re-downloading: {file_path.name}")
                try:
                    file_path.unlink()
                except Exception as e:
                    builtins.print(f"  ⚠️  Could not delete mismatched file: {e}")
                return True
        
        # Check if local file matches metadata
        metadata = self.file_metadata[item_id]
        local_size = file_path.stat().st_size
        
        # If sizes don't match, delete and re-download
        if local_size != metadata.get('size') or local_size != file_size:
            builtins.print(f"  Size mismatch, re-downloading: {file_path.name}")
            try:
                file_path.unlink()
            except Exception as e:
                builtins.print(f"  ⚠️  Could not delete mismatched file: {e}")
            return True
        
        # Verify hash if available
        if 'hash' in metadata:
            local_hash = self.calculate_file_hash(file_path)
            if local_hash != metadata['hash']:
                builtins.print(f"  Hash mismatch (corrupted), re-downloading: {file_path.name}")
                try:
                    file_path.unlink()
                except Exception as e:
                    builtins.print(f"  ⚠️  Could not delete corrupted file: {e}")
                return True
        
        # File is identical, skip download
        return False
    
    def load_metadata(self, backup_root):
        """Load existing backup metadata for incremental backups"""
        self.metadata_file = backup_root / ".backup_metadata.json"
        
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    data = json.load(f)
                    raw_metadata = data.get('files', {})
                
                # Cleanse metadata: Remove 0-byte entries (from Files On-Demand placeholders)
                original_count = len(raw_metadata)
                self.file_metadata = {
                    item_id: file_info 
                    for item_id, file_info in raw_metadata.items() 
                    if file_info.get('size', 0) > 0  # Only keep files with actual size
                }
                
                cleansed_count = original_count - len(self.file_metadata)
                
                builtins.print(f"Loaded metadata for {len(self.file_metadata)} existing files")
                if cleansed_count > 0:
                    builtins.print(f"Cleansed {cleansed_count} zero-byte entries from metadata")
                    builtins.print(f"   (These were likely Files On-Demand placeholders)")
                
            except Exception as e:
                builtins.print(f"⚠️  Could not load metadata: {e}")
                self.file_metadata = {}
    
    def save_metadata(self):
        """Save backup metadata for future incremental backups (thread-safe)"""
        if self.metadata_file:
            try:
                # Create thread-safe snapshot
                with self.progress_lock:
                    metadata_snapshot = dict(self.file_metadata)
                
                # Write snapshot to file
                with open(self.metadata_file, 'w') as f:
                    json.dump({
                        'files': metadata_snapshot,
                        'last_backup': datetime.now().isoformat()
                    }, f, indent=2)
            except Exception as e:
                builtins.print(f"⚠️  Could not save metadata: {e}")
    
    def login_to_onedrive_api(self):
        """Login to OneDrive using Microsoft Graph API"""
        builtins.print("\n" + "="*50)
        builtins.print("OneDrive Online Login")
        builtins.print("="*50)
        builtins.print("\n⚠️  IMPORTANT LIMITATIONS:")
        builtins.print("- Personal Microsoft accounts don't support device code flow")
        builtins.print("- You'll need to create a Microsoft App Registration")
        builtins.print("- This requires some technical setup")
        builtins.print("\nSetup Instructions:")
        builtins.print("1. Go to: https://portal.azure.com")
        builtins.print("2. Search for 'App registrations' <-’ New registration")
        builtins.print("3. Name: 'OneDrive Backup' (any name)")
        builtins.print("4. Supported account types: 'Personal Microsoft accounts only'")
        builtins.print("5. Register the app")
        builtins.print("6. Go to 'Certificates & secrets' <-’ New client secret")
        builtins.print("7. Copy the Client ID and Client Secret")
        builtins.print("8. Go to 'API permissions' <-’ Add permission <-’ Microsoft Graph")
        builtins.print("9. Add: Files.Read.All (Delegated)")
        builtins.print("10. Grant admin consent")
        builtins.print("\n⚠️  NOTE: This is complex. Alternative: Download files to local OneDrive first")
        builtins.print("="*50 + "\n")
        
        choice = input("Choose login method:\n1. App Credentials (Personal Account)\n2. Device Code (Work/School Only)\n3. Skip\nEnter choice: ").strip()
        
        if choice == '1':
            return self.app_credentials_auth()
        elif choice == '2':
            builtins.print("\n⚠️  Warning: Device code only works with work/school accounts")
            confirm = input("Do you have a work/school account? (y/n): ").strip().lower()
            if confirm == 'y':
                return self.device_code_auth()
            else:
                builtins.print("Returning to main menu...")
                return False
        else:
            return False
    
    def device_code_auth(self):
        """Authenticate using device code flow (no app registration needed)"""
        builtins.print("\nDevice Code Authentication")
        builtins.print("This method is more secure and doesn't require app registration\n")
        
        # Using Microsoft's public client ID for device code flow
        client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"  # Microsoft Office client
        authority = "https://login.microsoftonline.com/common"
        
        # Request device code
        device_code_url = f"{authority}/oauth2/v2.0/devicecode"
        data = {
            'client_id': client_id,
            'scope': 'https://graph.microsoft.com/Files.Read.All offline_access'
        }
        
        try:
            response = requests.post(device_code_url, data=data)
            device_code_data = response.json()
            
            if 'error' in device_code_data:
                builtins.print(f"❌ Error: {device_code_data.get('error_description', 'Unknown error')}")
                return False
            
            builtins.print("\n" + "="*50)
            builtins.print("AUTHENTICATION REQUIRED")
            builtins.print("="*50)
            builtins.print(f"\n1. Go to: {device_code_data['verification_uri']}")
            builtins.print(f"2. Enter code: {device_code_data['user_code']}")
            builtins.print(f"3. Sign in with your Microsoft account")
            builtins.print(f"\nWaiting for authentication (expires in {device_code_data['expires_in']//60} minutes)...")
            builtins.print("="*50 + "\n")
            
            # Poll for token
            token_url = f"{authority}/oauth2/v2.0/token"
            token_data = {
                'client_id': client_id,
                'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
                'device_code': device_code_data['device_code']
            }
            
            interval = device_code_data.get('interval', 5)
            expires_at = time.time() + device_code_data['expires_in']
            
            while time.time() < expires_at:
                time.sleep(interval)
                token_response = requests.post(token_url, data=token_data)
                token_result = token_response.json()
                
                if 'access_token' in token_result:
                    self.access_token = token_result['access_token']
                    self.use_api = True
                    builtins.print("✅ Successfully authenticated!\n")
                    return True
                elif token_result.get('error') == 'authorization_pending':
                    builtins.print("⏳ Waiting for authentication...", end='\r')
                    continue
                elif token_result.get('error') == 'authorization_declined':
                    builtins.print("\n❌ Authentication declined")
                    return False
                elif token_result.get('error') == 'expired_token':
                    builtins.print("\n❌ Authentication expired")
                    return False
                else:
                    builtins.print(f"\n❌ Error: {token_result.get('error_description', 'Unknown error')}")
                    return False
            
            builtins.print("\n⏱️  Authentication timeout")
            return False
            
        except Exception as e:
            builtins.print(f"❌ Authentication error: {e}")
            return False
    
    def app_credentials_auth(self):
        """Authenticate using app credentials (requires app registration)"""
        builtins.print("\nApp Credentials Authentication")
        self.client_id = input("Enter Application (client) ID: ").strip()
        self.client_secret = getpass.getpass("Enter Client Secret (hidden): ")
        self.tenant_id = input("Enter Tenant ID (or 'common' for personal): ").strip() or "common"
        
        authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        
        # For personal accounts, we need delegated permissions with auth code flow
        if self.tenant_id == "common":
            return self.delegated_auth_flow()
        
        # For work/school, use client credentials
        token_url = f"{authority}/oauth2/v2.0/token"
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'https://graph.microsoft.com/.default',
            'grant_type': 'client_credentials'
        }
        
        try:
            response = requests.post(token_url, data=data)
            result = response.json()
            
            if 'access_token' in result:
                self.access_token = result['access_token']
                self.use_api = True
                builtins.print("✅ Successfully authenticated!\n")
                return True
            else:
                builtins.print(f"❌ Authentication failed: {result.get('error_description', 'Unknown error')}")
                return False
        except Exception as e:
            builtins.print(f"❌ Authentication error: {e}")
            return False
    
    def delegated_auth_flow(self):
        """Interactive auth flow for personal accounts"""
        builtins.print("\nStarting interactive authentication...")
        builtins.print("A browser window will open for you to sign in.")
        
        # Generate auth URL
        redirect_uri = "http://localhost:8080"
        scope = "Files.Read.All offline_access"
        auth_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/authorize"
        auth_url += f"?client_id={self.client_id}"
        auth_url += f"&response_type=code"
        auth_url += f"&redirect_uri={redirect_uri}"
        auth_url += f"&scope={scope}"
        
        builtins.print(f"\n1. Opening browser...")
        builtins.print(f"2. Sign in with your Microsoft account")
        builtins.print(f"3. After approving, you'll be redirected to localhost")
        builtins.print(f"4. Copy the 'code=' value from the URL\n")
        
        webbrowser.open(auth_url)
        
        builtins.print("After signing in, your browser will show an error page.")
        builtins.print("That's normal! Just copy the URL from your browser.")
        redirect_response = input("\nPaste the full redirect URL here: ").strip()
        
        # Extract code from URL
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(redirect_response)
            code = parse_qs(parsed.query)['code'][0]
        except:
            builtins.print("❌ Could not extract authorization code from URL")
            return False
        
        # Exchange code for tokens
        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
        }
        
        try:
            response = requests.post(token_url, data=data)
            result = response.json()
            
            if 'access_token' in result:
                self.access_token = result['access_token']
                self.refresh_token = result.get('refresh_token')
                self.use_api = True
                builtins.print("✅ Successfully authenticated!\n")
                return True
            else:
                builtins.print(f"❌ Token exchange failed: {result.get('error_description', 'Unknown error')}")
                return False
        except Exception as e:
            builtins.print(f"❌ Authentication error: {e}")
            return False
    
    def refresh_access_token(self):
        """Refresh the access token using refresh token"""
        if not self.refresh_token:
            return False
        
        builtins.print("Refreshing access token...")
        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': self.refresh_token,
            'grant_type': 'refresh_token'
        }
        
        try:
            response = requests.post(token_url, data=data)
            result = response.json()
            
            if 'access_token' in result:
                self.access_token = result['access_token']
                self.refresh_token = result.get('refresh_token', self.refresh_token)
                builtins.print("Token refreshed!")
                return True
            else:
                builtins.print(f"❌ Token refresh failed: {result.get('error_description', 'Unknown error')}")
                return False
        except Exception as e:
            builtins.print(f"❌ Token refresh error: {e}")
            return False
    
    def download_large_file(self, url, destination, filename, expected_size, depth=0, item_id=None):
        """
        Download large files in chunks with progress tracking and resume capability.
        
        Features:
        - Adaptive chunk size (50MB for huge files, 20MB for large, 10MB for normal)
        - Resume capability if download is interrupted
        - Real-time progress tracking with speed and ETA
        - Automatic retry on timeout
        - Graceful handling of interruptions
        - Post-download verification
        - Proactive URL refresh for huge files (>10GB)
        """
        # Adaptive chunk size based on file size
        if expected_size > 10 * 1024 * 1024 * 1024:  # > 10 GB
            chunk_size = 50 * 1024 * 1024  # 50 MB chunks for huge files
            builtins.print(f"  {'  ' * depth}Huge file detected ({expected_size/(1024**3):.1f}GB), using 50MB chunks")
        elif expected_size > 1 * 1024 * 1024 * 1024:  # > 1 GB
            chunk_size = 20 * 1024 * 1024  # 20 MB chunks for large files
        else:
            chunk_size = 10 * 1024 * 1024  # 10 MB chunks for normal files
        
        temp_file = destination.parent / f".{destination.name}.download"
        
        # Check if partial download exists
        downloaded_size = 0
        if temp_file.exists():
            downloaded_size = temp_file.stat().st_size
            builtins.print(f"  {'  ' * depth}Resuming {filename} from {downloaded_size / (1024*1024):.1f}MB")
        
        max_retries = 3
        retry_count = 0
        download_start_time = time.time()
        last_url_refresh_time = download_start_time
        url_refresh_interval = 60 * 60  # Refresh URL every 60 minutes for huge files
        
        while retry_count < max_retries:
            try:
                # Make request with range header if resuming
                headers_with_range = {}
                if downloaded_size > 0:
                    headers_with_range['Range'] = f'bytes={downloaded_size}-'
                
                response = requests.get(url, headers=headers_with_range, stream=True, timeout=60)
                
                # If server doesn't support resume (206), start fresh
                if downloaded_size > 0 and response.status_code not in [200, 206]:
                    if response.status_code == 416:  # Range not satisfiable - file might be complete
                        # Check if temp file size matches what we expect
                        if temp_file.exists():
                            temp_file.rename(destination)
                            # Verify the file
                            if self.verify_file(destination, expected_size, item_id):
                                class SuccessResponse:
                                    status_code = 200
                                return SuccessResponse()
                            else:
                                builtins.print(f"  {'  ' * depth}❌ Verification failed, re-downloading")
                                destination.unlink()
                                downloaded_size = 0
                                continue
                    
                    builtins.print(f"  {'  ' * depth}⚠️  Server doesn't support resume (status {response.status_code}), starting fresh")
                    downloaded_size = 0
                    if temp_file.exists():
                        temp_file.unlink()
                    response = requests.get(url, stream=True, timeout=60)
                
                if response.status_code not in [200, 206]:
                    # If 401 and we're just starting, try to get a fresh download URL
                    if response.status_code == 401 and downloaded_size == 0 and item_id:
                        builtins.print(f"\n  {'  ' * depth}{filename}: Download URL expired, refreshing...")
                        fresh_url = self.get_fresh_download_url(item_id)
                        if fresh_url:
                            url = fresh_url  # Update URL for next retry
                            continue  # Retry with fresh URL
                        else:
                            builtins.print(f"  {'  ' * depth}❌ Could not refresh download URL")
                            return None
                    
                    builtins.print(f"  {'  ' * depth}❌ HTTP {response.status_code} received")
                    return response
                
                # Get total file size
                if response.status_code == 206:
                    # Partial content - parse Content-Range header
                    content_range = response.headers.get('Content-Range', '')
                    if '/' in content_range:
                        total_size = int(content_range.split('/')[-1])
                    else:
                        total_size = int(response.headers.get('content-length', 0)) + downloaded_size
                else:
                    # Full content
                    total_size = int(response.headers.get('content-length', 0))
                
                # Open file in append mode if resuming, write mode if starting fresh
                mode = 'ab' if downloaded_size > 0 and response.status_code == 206 else 'wb'
                if mode == 'wb':
                    downloaded_size = 0  # Reset if starting fresh
                
                with open(temp_file, mode) as f:
                    start_time = time.time()
                    last_print_time = start_time
                    chunk_start_time = start_time
                    chunk_start_size = downloaded_size
                    
                    for chunk in response.iter_content(chunk_size=chunk_size):
                        if chunk:
                            f.write(chunk)
                            downloaded_size += len(chunk)
                            
                            # Print progress every 2 seconds
                            current_time = time.time()
                            
                            # For huge files (>10GB), proactively refresh URL every 60 minutes
                            if expected_size > 10 * 1024 * 1024 * 1024 and item_id:
                                if current_time - last_url_refresh_time >= url_refresh_interval:
                                    builtins.print(f"\n  {'  ' * depth}Proactive URL refresh (60 min elapsed)...")
                                    fresh_url = self.get_fresh_download_url(item_id)
                                    if fresh_url:
                                        builtins.print(f"  {'  ' * depth}✓ Fresh URL obtained, continuing download...")
                                        url = fresh_url
                                        last_url_refresh_time = current_time
                                        # Save progress and restart with fresh URL
                                        f.flush()
                                        # Break and restart with new URL
                                        break
                                    else:
                                        builtins.print(f"  {'  ' * depth}⚠️  Could not refresh URL proactively, continuing...")
                            
                            if current_time - last_print_time >= 2 or downloaded_size >= total_size:
                                # Calculate speed based on recent chunks for more accuracy
                                time_delta = current_time - chunk_start_time
                                if time_delta > 0:
                                    recent_speed = (downloaded_size - chunk_start_size) / time_delta / (1024 * 1024)  # MB/s
                                else:
                                    recent_speed = 0
                                
                                percent = (downloaded_size / total_size * 100) if total_size > 0 else 0
                                eta = (total_size - downloaded_size) / (recent_speed * 1024 * 1024) if recent_speed > 0 else 0
                                
                                # Format ETA nicely
                                if eta > 3600:
                                    eta_str = f"{eta/3600:.1f}h"
                                elif eta > 60:
                                    eta_str = f"{eta/60:.1f}m"
                                else:
                                    eta_str = f"{eta:.0f}s"
                                
                                builtins.print(f"  {'  ' * depth}{filename[:35]}: {downloaded_size/(1024*1024):.1f}/{total_size/(1024*1024):.1f}MB ({percent:.1f}%) @ {recent_speed:.2f}MB/s, ETA: {eta_str}     ", end='\r')
                                last_print_time = current_time
                                
                                # Reset chunk timing for next calculation
                                chunk_start_time = current_time
                                chunk_start_size = downloaded_size
                    
                    # If we broke out for URL refresh, continue with new URL
                    if downloaded_size < total_size and expected_size > 10 * 1024 * 1024 * 1024:
                        continue  # Retry with fresh URL
                
                # Download complete, move temp file to final location
                if temp_file.exists():
                    temp_file.rename(destination)
                
                builtins.print()  # New line after progress
                
                # Verify the downloaded file
                if not self.verify_file(destination, expected_size, item_id):
                    with self.progress_lock:
                        self.verification_failures.append(str(destination))
                    builtins.print(f"  {'  ' * depth}⚠️  Verification failed for {filename}")
                    # Don't return error - file is downloaded, just flagged for review
                
                # Create a success response object
                class SuccessResponse:
                    status_code = 200
                
                return SuccessResponse()
                
            except requests.exceptions.Timeout:
                retry_count += 1
                if retry_count < max_retries:
                    builtins.print(f"\n  {'  ' * depth}⏱️  Timeout for {filename}, retrying ({retry_count}/{max_retries})...")
                    time.sleep(5)  # Wait before retry
                    continue
                else:
                    builtins.print(f"\n  {'  ' * depth}❌ Max retries reached for {filename}, progress saved")
                    return None
                    
            except requests.exceptions.RequestException as e:
                retry_count += 1
                if retry_count < max_retries:
                    builtins.print(f"\n  {'  ' * depth}⚠️  Network error for {filename}, retrying ({retry_count}/{max_retries}): {e}")
                    time.sleep(5)
                    continue
                else:
                    builtins.print(f"\n  {'  ' * depth}❌ Max retries reached for {filename}: {e}")
                    return None
                    
            except KeyboardInterrupt:
                builtins.print(f"\n  {'  ' * depth}⏸️  Download interrupted for {filename}, progress saved to {temp_file.name}")
                raise  # Re-raise to be caught by main handler
                
            except Exception as e:
                builtins.print(f"\n  {'  ' * depth}❌ Error downloading {filename}: {e}")
                if temp_file.exists() and downloaded_size == 0:
                    temp_file.unlink()  # Clean up corrupted temp file only if we haven't made progress
                return None
        
        return None  # If we exit the retry loop without success
    
    def get_fresh_download_url(self, item_id):
        """Get a fresh download URL for an item when the old one expires"""
        try:
            item_url = f"https://graph.microsoft.com/v1.0/me/drive/items/{item_id}"
            response = requests.get(item_url, headers=self.api_headers, timeout=30)
            
            if response.status_code == 401:
                # Token expired, refresh and retry
                if self.refresh_access_token():
                    self.api_headers['Authorization'] = f'Bearer {self.access_token}'
                    response = requests.get(item_url, headers=self.api_headers, timeout=30)
            
            if response.status_code == 200:
                item_data = response.json()
                return item_data.get('@microsoft.graph.downloadUrl')
        except Exception as e:
            builtins.print(f"  ⚠️  Failed to refresh download URL: {e}")
        
        return None
    
    def download_single_file(self, download_task):
        """
        Download a single file (used by thread pool).
        
        Args:
            download_task: Dictionary containing file info
            
        Returns:
            dict: Result of download operation
        """
        item = download_task['item']
        local_path = download_task['local_path']
        depth = download_task['depth']
        backup_root = download_task['backup_root']
        
        name = item['name']
        item_id = item['id']
        file_size = item.get('size', 0)
        download_url = item.get('@microsoft.graph.downloadUrl')
        
        file_path = local_path / name
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        result = {
            'item_id': item_id,
            'name': name,
            'path': file_path,
            'size': file_size,
            'success': False,
            'skipped': False,
            'error': None
        }
        
        # Check if we can skip this file (incremental backup)
        if not self.should_download_file(item_id, file_size, file_path):
            result['skipped'] = True
            result['success'] = True
            with self.progress_lock:
                self.downloaded_files[item_id] = {
                    'size': file_size,
                    'path': str(file_path),
                    'timestamp': datetime.now().isoformat()
                }
            return result
        
        if not download_url:
            result['error'] = "No download URL available"
            return result
        
        try:
            # Use chunked download for large files
            if file_size > self.large_file_threshold:
                file_response = self.download_large_file(download_url, file_path, name, file_size, depth, item_id)
            else:
                # Small file - simple download with verification
                file_response = requests.get(download_url, timeout=300)
                
                # If 401, the download URL expired - get a fresh one
                if file_response.status_code == 401:
                    builtins.print(f"  {name}: Download URL expired, refreshing...")
                    fresh_url = self.get_fresh_download_url(item_id)
                    if fresh_url:
                        file_response = requests.get(fresh_url, timeout=300)
                    else:
                        result['error'] = "Download URL expired and could not be refreshed"
                        builtins.print(f"  ❌ {name}: Could not refresh download URL")
                        return result
                
                if file_response.status_code == 200:
                    with open(file_path, 'wb') as f:
                        f.write(file_response.content)
                    
                    # Verify small file
                    if not self.verify_file(file_path, file_size, item_id):
                        with self.progress_lock:
                            self.verification_failures.append(str(file_path))
                        builtins.print(f"  ⚠️  Verification failed for {name}")
            
            if file_response and file_response.status_code == 200:
                result['success'] = True
                # Only track files with actual content
                if file_size > 0:
                    with self.progress_lock:
                        self.downloaded_files[item_id] = {
                            'size': file_size,
                            'path': str(file_path),
                            'timestamp': datetime.now().isoformat()
                        }
                else:
                    builtins.print(f"  ⚠️  Skipping 0-byte file from progress: {name}")
                
                # Print success message
                rel_path = file_path.relative_to(backup_root)
                size_mb = file_size / (1024 * 1024)
                with self.progress_lock:
                    builtins.print(f"  ✓ {rel_path} ({size_mb:.1f}MB)")
            elif file_response:
                result['error'] = f"HTTP {file_response.status_code}"
                builtins.print(f"  ❌ {name}: HTTP {file_response.status_code}")
            
        except Exception as e:
            error_msg = str(e)
            result['error'] = error_msg
            builtins.print(f"  ✗ {name}: {error_msg}")
        
        return result
    
    def _run_download_phase(self, files_to_download, save_progress_func, backup_root):
        """
        Run Phase 3: Download files with multi-threading.

        Args:
            files_to_download: List of file tasks to download
            save_progress_func: Function to save progress
            backup_root: Path to backup root directory

        Returns:
            dict or bool: {'success': bool, 'failed_count': int, 'downloaded_count': int} or False on error
        """
        builtins.print(f"\nPhase 3: Downloading {len(files_to_download)} files using {self.max_workers} parallel threads...\n")

        downloaded_count = 0
        skipped_count = 0
        failed_count = 0
        failed_files = []  # Track failed files with reasons

        def save_progress():
            """Save current progress (thread-safe)"""
            # Create a snapshot while holding the lock to avoid "dictionary changed size during iteration"
            with self.progress_lock:
                files_snapshot = dict(self.downloaded_files)

            # Write snapshot to file (no lock needed for file I/O)
            with open(self.progress_file, 'w') as f:
                json.dump({
                    'downloaded_files': files_snapshot,
                    'timestamp': datetime.now().isoformat()
                }, f)
            self.save_metadata()

        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all download tasks
                future_to_file = {executor.submit(self.download_single_file, task): task for task in files_to_download}

                # Process completed downloads
                for future in as_completed(future_to_file):
                    task = future_to_file[future]
                    result = future.result()

                    if result['success']:
                        if result['skipped']:
                            skipped_count += 1
                        else:
                            downloaded_count += 1
                    else:
                        failed_count += 1
                        # Track failure with reason
                        failed_files.append({
                            'name': result['name'],
                            'path': str(result['path']),
                            'error': result.get('error', 'Unknown error')
                        })

                    # Save progress every 10 files
                    if (downloaded_count + skipped_count + failed_count) % 10 == 0:
                        save_progress()

                    # Show progress
                    total_processed = downloaded_count + skipped_count + failed_count
                    builtins.print(f"  Progress: {total_processed}/{len(files_to_download)} (Downloaded: {downloaded_count}, Skipped: {skipped_count}, Failed: {failed_count})", end='\r')

            builtins.print()  # New line after progress

            # Final save
            save_progress()

            # Print summary
            builtins.print("\n" + "="*50)
            builtins.print("BACKUP SUMMARY")
            builtins.print("="*50)
            builtins.print(f"Total files processed: {len(files_to_download)}")
            builtins.print(f"Successfully downloaded: {downloaded_count}")
            builtins.print(f"Skipped (unchanged): {skipped_count}")
            builtins.print(f"Failed: {failed_count}")
            builtins.print(f"Backup location: {backup_root}")

            # List failed files with reasons
            if failed_files:
                builtins.print(f"\n❌ Failed Files ({len(failed_files)} total):")
                builtins.print("-" * 50)

                # Categorize failures
                dns_failures = []
                network_failures = []
                http_failures = []
                other_failures = []

                for failed in failed_files:
                    error = failed['error']
                    if 'Failed to resolve' in error or 'nodename nor servname' in error:
                        dns_failures.append(failed)
                    elif 'IncompleteRead' in error or 'Connection broken' in error:
                        network_failures.append(failed)
                    elif 'HTTP' in error:
                        http_failures.append(failed)
                    else:
                        other_failures.append(failed)

                # Show DNS failures
                if dns_failures:
                    builtins.print(f"\nDNS Resolution Errors ({len(dns_failures)} files):")
                    builtins.print("   Cause: Temporary DNS issues")
                    builtins.print("   Action: Retry - these should work on second attempt\n")
                    for failed in dns_failures[:5]:  # Show first 5
                        # Show relative path from backup root for clarity
                        try:
                            rel_path = Path(failed['path']).relative_to(backup_root)
                            builtins.print(f"   • {rel_path}")
                        except:
                            builtins.print(f"   • {failed['name']}")
                    if len(dns_failures) > 5:
                        builtins.print(f"   ... and {len(dns_failures) - 5} more")

                # Show network failures
                if network_failures:
                    builtins.print(f"\nNetwork Connection Errors ({len(network_failures)} files):")
                    builtins.print("   Cause: Download interrupted mid-transfer")
                    builtins.print("   Action: Retry - these should work on second attempt\n")
                    for failed in network_failures[:5]:
                        try:
                            rel_path = Path(failed['path']).relative_to(backup_root)
                            builtins.print(f"   • {rel_path}")
                        except:
                            builtins.print(f"   • {failed['name']}")
                        if len(failed['error']) < 100:  # Show short errors
                            builtins.print(f"     Error: {failed['error']}")
                    if len(network_failures) > 5:
                        builtins.print(f"   ... and {len(network_failures) - 5} more")

                # Show HTTP failures
                if http_failures:
                    builtins.print(f"\n⚠️  HTTP Errors ({len(http_failures)} files):")
                    builtins.print("   Cause: Server returned error")
                    builtins.print("   Action: May need manual intervention\n")
                    for failed in http_failures[:5]:
                        try:
                            rel_path = Path(failed['path']).relative_to(backup_root)
                            builtins.print(f"   • {rel_path} - {failed['error']}")
                        except:
                            builtins.print(f"   • {failed['name']} - {failed['error']}")
                    if len(http_failures) > 5:
                        builtins.print(f"   ... and {len(http_failures) - 5} more")

                # Show other failures
                if other_failures:
                    builtins.print(f"\n❓ Other Errors ({len(other_failures)} files):")
                    for failed in other_failures[:5]:
                        try:
                            rel_path = Path(failed['path']).relative_to(backup_root)
                            builtins.print(f"   • {rel_path}")
                        except:
                            builtins.print(f"   • {failed['name']}")
                        builtins.print(f"     Error: {failed['error'][:100]}")
                    if len(other_failures) > 5:
                        builtins.print(f"   ... and {len(other_failures) - 5} more")

                builtins.print(f"\nTo retry failed files, run the script again with the same settings.")
                builtins.print(f"   The script will skip successfully downloaded files and only retry the {len(failed_files)} that failed.")

            if self.verification_failures:
                builtins.print(f"\n⚠️  Verification Warnings ({len(self.verification_failures)} files):")
                for failed_file in self.verification_failures[:10]:
                    builtins.print(f"  - {failed_file}")
                if len(self.verification_failures) > 10:
                    builtins.print(f"  ... and {len(self.verification_failures) - 10} more")
                builtins.print("\nThese files downloaded but failed verification. They may be corrupt.")
                builtins.print("Consider re-downloading them or checking manually.")

            builtins.print(f"\nFolder structure preserved exactly as in OneDrive!")

            # Clean up progress file on successful completion
            if self.progress_file.exists() and failed_count == 0:
                self.progress_file.unlink()

            return {'success': True, 'failed_count': failed_count, 'downloaded_count': downloaded_count}

        except KeyboardInterrupt:
            builtins.print("\n\n⏸️  Backup interrupted by user.")
            save_progress()
            builtins.print(f"Progress saved! Run the script again to resume from where you left off.")
            builtins.print(f"Downloaded so far: {downloaded_count} files")
            return {'success': False, 'failed_count': failed_count, 'downloaded_count': downloaded_count}
        except Exception as e:
            builtins.print(f"❌ Download error: {e}")
            save_progress()
            builtins.print(f"Progress saved. You can resume by running the script again.")
            return {'success': False, 'failed_count': failed_count, 'downloaded_count': downloaded_count}

    def download_from_api(self, destination_drive, include_docs=True, include_pics=True, include_videos=True, include_all=False, resume_backup_path=None, skip_scan=False):
        """Download files using Microsoft Graph API with multi-threading

        Args:
            skip_scan: If True, skip scanning and download files found in previous scan
        """
        # Immediate feedback - user sees this right away
        builtins.print("[STARTUP] Preparing backup...")
        
        if not self.access_token:
            builtins.print("❌ Not authenticated")
            return False
        
        builtins.print("[STARTUP] Authentication verified")
        
        destination = Path(destination_drive)
        if not destination.exists():
            builtins.print(f"❌ Destination drive '{destination_drive}' not found!")
            return False
        
        builtins.print("[STARTUP] Destination drive ready")
        
        # Use the backup path passed from main() if resuming
        if resume_backup_path:
            backup_root = resume_backup_path
            builtins.print(f"\n✓ Resuming backup: {backup_root.name}")
        else:
            # Create new backup
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_root = destination / f"OneDrive_Backup_{timestamp}"
            backup_root.mkdir(exist_ok=True)
            builtins.print(f"\n✓ Starting new backup: {backup_root.name}")

        # Send the backup path to UI so it can be used for resume
        if self.progress_callback:
            self.progress_callback('backup_path', {'path': str(backup_root)})
        
        # Load metadata for incremental backup
        builtins.print("[STARTUP] Loading previous backup data...")
        self.load_metadata(backup_root)

        # Progress tracking
        self.progress_file = backup_root / ".progress.json"
        scanned_folder_ids = set()  # Folder IDs that have been fully scanned
        pending_folder_urls = []  # Folder URLs that still need to be scanned (for resume)
        saved_files_to_download = []  # Files found during previous scan
        partial_scan = False  # Track if this was a partial scan (user clicked Download Now)

        if self.progress_file.exists():
            with open(self.progress_file, 'r') as f:
                progress_data = json.load(f)
                raw_downloaded = progress_data.get('downloaded_files', {})
                scanned_folder_ids = set(progress_data.get('scanned_folder_ids', []))
                saved_files_to_download = progress_data.get('files_to_download', [])
                pending_folder_urls = progress_data.get('pending_folder_urls', [])
                partial_scan = progress_data.get('partial_scan', False)

            # Cleanse progress: Remove 0-byte entries
            original_count = len(raw_downloaded)
            self.downloaded_files = {
                item_id: file_info
                for item_id, file_info in raw_downloaded.items()
                if file_info.get('size', 0) > 0  # Only keep files with actual size
            }

            cleansed_count = original_count - len(self.downloaded_files)

            builtins.print(f"Loaded progress: {len(self.downloaded_files)} files already downloaded")
            if scanned_folder_ids:
                builtins.print(f"Loaded scan progress: {len(scanned_folder_ids)} folders already scanned")
            if saved_files_to_download:
                builtins.print(f"Loaded {len(saved_files_to_download)} files from previous scan")
            if pending_folder_urls:
                builtins.print(f"Found {len(pending_folder_urls)} folders pending from previous partial scan")
            if partial_scan:
                builtins.print(f"Previous backup was a partial scan - will continue scanning remaining folders")
            if cleansed_count > 0:
                builtins.print(f"Cleansed {cleansed_count} zero-byte entries from progress")
                builtins.print(f"   (These files will be re-downloaded properly)")
            builtins.print()

            # Send initial resume state to UI so it shows previous progress
            if self.progress_callback and (saved_files_to_download or self.downloaded_files):
                total_size_from_saved = sum(f['item'].get('size', 0) for f in saved_files_to_download)
                self.progress_callback('resume_state', {
                    'files_to_download': len(saved_files_to_download),
                    'files_downloaded': len(self.downloaded_files),
                    'folders_scanned': len(scanned_folder_ids),
                    'pending_folders': len(pending_folder_urls),
                    'partial_scan': partial_scan,
                    'estimated_size': total_size_from_saved
                })

        builtins.print(f"Backup destination: {backup_root}\n")
        
        # Create headers dict that we can update when refreshing tokens
        self.api_headers = {'Authorization': f'Bearer {self.access_token}'}
        
        # PHASE 1: Scan and calculate total size
        builtins.print("Phase 1: Scanning OneDrive and calculating space requirements...\n")
        
        builtins.print("[STARTUP] Connecting to OneDrive...")
        
        graph_url = "https://graph.microsoft.com/v1.0/me/drive/root/children"

        # Use class-level extension constants
        doc_extensions = self.DOC_EXTENSIONS
        pic_extensions = self.PIC_EXTENSIONS
        video_extensions = self.VIDEO_EXTENSIONS

        total_size_bytes = 0
        scanned_files = 0
        skipped_files = 0
        consecutive_refresh_failures = 0
        last_save_time = time.time()

        # Initialize files_to_download from saved progress if available
        # Convert saved paths back to Path objects
        files_to_download = []
        if saved_files_to_download:
            builtins.print(f"✓ Resuming scan from saved progress...")
            builtins.print(f"  Already found: {len(saved_files_to_download)} files")
            builtins.print(f"  Folders completed: {len(scanned_folder_ids)}")
            builtins.print()

        for saved_file in saved_files_to_download:
            files_to_download.append({
                'item': saved_file['item'],
                'local_path': Path(saved_file['local_path']),
                'depth': saved_file['depth'],
                'backup_root': backup_root
            })
            total_size_bytes += saved_file['item'].get('size', 0)
            scanned_files += 1

        # Skip scan and go directly to downloads if requested (Download Now from paused state)
        if skip_scan:
            if not files_to_download:
                builtins.print("❌ No files to download. Please run a scan first.")
                if self.progress_callback:
                    self.progress_callback('error', {'message': 'No files to download. Please run a scan first.'})
                return False

            builtins.print(f"\n📥 Skipping scan - downloading {len(files_to_download)} files from previous scan...")
            builtins.print(f"  Total size: {self.format_size(total_size_bytes)}")
            if self.progress_callback:
                self.progress_callback('log', {
                    'type': 'info',
                    'message': f'Downloading {len(files_to_download)} files from previous scan ({self.format_size(total_size_bytes)})',
                    'icon': '📥'
                })

            # Jump directly to Phase 2 (disk space check) and Phase 3 (downloads)
            # We need to define save_scan_progress for the download phase
            def save_scan_progress(is_partial=False, pending_urls=None):
                nonlocal last_save_time
                serializable_files = []
                for f in files_to_download:
                    serializable_files.append({
                        'item': f['item'],
                        'local_path': str(f['local_path']),
                        'depth': f['depth']
                    })
                progress_data = {
                    'downloaded_files': self.downloaded_files,
                    'scanned_folder_ids': list(scanned_folder_ids),
                    'files_to_download': serializable_files,
                    'scan_in_progress': False,
                    'partial_scan': True,
                    'pending_folder_urls': pending_folder_urls
                }
                with open(self.progress_file, 'w') as f:
                    json.dump(progress_data, f)
                last_save_time = time.time()

            # Go to Phase 2
            builtins.print("\nPhase 2: Checking available disk space...\n")
            has_space, available, required = self.check_disk_space(destination, total_size_bytes)
            builtins.print(f"  Available space: {self.format_size(available)}")
            builtins.print(f"  Required space: {self.format_size(required)} (including 10% buffer)")

            if not has_space:
                builtins.print(f"\nERROR: Insufficient disk space!")
                return False

            builtins.print(f"  Sufficient space available\n")

            # Go to Phase 3 - download
            return self._run_download_phase(files_to_download, save_scan_progress, backup_root)

        def save_scan_progress(is_partial=False, pending_urls=None):
            """Save current scan progress to allow resumption

            Args:
                is_partial: If True, marks this as a partial scan (user clicked Download Now)
                pending_urls: List of folder URLs still to be scanned (for resume)
            """
            nonlocal last_save_time
            # Convert files_to_download to JSON-serializable format
            serializable_files = []
            for f in files_to_download:
                serializable_files.append({
                    'item': f['item'],
                    'local_path': str(f['local_path']),
                    'depth': f['depth']
                })

            progress_data = {
                'downloaded_files': self.downloaded_files,
                'scanned_folder_ids': list(scanned_folder_ids),
                'files_to_download': serializable_files,
                'scan_in_progress': True,
                'partial_scan': is_partial,
                'pending_folder_urls': pending_urls or []
            }
            with open(self.progress_file, 'w') as f:
                json.dump(progress_data, f)
            last_save_time = time.time()

        def extract_folder_id(url):
            """Extract folder ID from Graph API URL"""
            if '/root/children' in url:
                return 'root'
            # URL format: .../drive/items/{item_id}/children
            import re
            match = re.search(r'/items/([^/]+)/children', url)
            return match.group(1) if match else None
        
        def make_api_request(url, retry_count=0, max_retries=3):
            """Make API request with automatic token refresh"""
            nonlocal consecutive_refresh_failures
            
            try:
                response = requests.get(url, headers=self.api_headers, timeout=30)
                
                if response.status_code == 401:
                    if self.refresh_token and consecutive_refresh_failures < 3:
                        builtins.print("\nAccess token expired, refreshing...")
                        if self.refresh_access_token():
                            # Update the global headers
                            self.api_headers['Authorization'] = f'Bearer {self.access_token}'
                            consecutive_refresh_failures = 0
                            builtins.print("✓ Token refreshed, retrying request...")
                            # Retry the request with new token
                            return make_api_request(url, retry_count, max_retries)
                        else:
                            consecutive_refresh_failures += 1
                            builtins.print(f"❌ Token refresh failed (attempt {consecutive_refresh_failures}/3)")
                            if consecutive_refresh_failures >= 3:
                                builtins.print("❌ Too many token refresh failures. Please re-authenticate.")
                                return None
                    else:
                        builtins.print("❌ Authentication failed and cannot refresh. Please re-run the script.")
                        return None
                
                if response.status_code == 200:
                    consecutive_refresh_failures = 0  # Reset on success
                    return response
                
                return response
                
            except requests.exceptions.Timeout:
                if retry_count < max_retries:
                    builtins.print(f"\n⏱️  Request timeout, retrying ({retry_count + 1}/{max_retries})...")
                    time.sleep(2)
                    return make_api_request(url, retry_count + 1, max_retries)
                else:
                    builtins.print(f"\n❌ Max retries reached for {url[:50]}...")
                    return None
            except requests.exceptions.RequestException as e:
                builtins.print(f"\n❌ Network error: {e}")
                return None
        
        connection_established = False
        total_items_processed = 0  # All items, not just matching files
        last_progress_time = time.time()

        # Per-folder tracking for real-time UI updates
        # root_folder_name: the top-level folder (depth 1) that gets its own log entry
        # current_subfolder: the subfolder path being scanned (shown in same log line)
        root_folder_name = None
        current_subfolder = None
        folder_items_scanned = 0
        folder_files_to_download = 0

        # Queue of folders to scan: (url, local_path, depth)
        # This allows us to track pending folders for early download resume
        folders_to_scan = []

        def scan_folder(url, local_path, depth=0):
            """Scan folder and collect files to download (with pagination support)"""
            nonlocal total_size_bytes, scanned_files, skipped_files, connection_established
            nonlocal total_items_processed, last_progress_time, last_save_time
            nonlocal root_folder_name, current_subfolder, folder_items_scanned, folder_files_to_download
            nonlocal scanned_folder_ids, folders_to_scan

            # Check if this folder was already scanned (resume support)
            folder_id = extract_folder_id(url)
            if folder_id and folder_id in scanned_folder_ids:
                if depth == 1 and local_path.name:
                    builtins.print(f"[SCANNING] Skipping already scanned folder: {local_path.name}")
                return  # Skip this folder entirely

            # Announce OneDrive folders so user sees activity
            # depth=0 is the backup root, depth=1+ are actual OneDrive folders
            if depth == 1 and local_path.name:
                # New top-level folder - reset counters and create new log entry
                root_folder_name = local_path.name
                current_subfolder = None
                folder_items_scanned = 0
                folder_files_to_download = 0
                builtins.print(f"[SCANNING] Entering folder: {local_path.name}")
                # Send initial folder progress (0 scanned, 0 to download)
                self.send_folder_progress(root_folder_name, 0, 0, depth=1, subfolder_path=None,
                                         total_scanned=total_items_processed, total_to_download=len(files_to_download))
            elif depth >= 2 and local_path.name:
                # Subfolder - update the current subfolder path
                current_subfolder = local_path.name

                # Handle resume case: if no root_folder_name set, use the deepest folder
                # This happens when resuming from pending folders at depth > 1
                if not root_folder_name:
                    root_folder_name = local_path.name
                    folder_items_scanned = 0
                    folder_files_to_download = 0
                    builtins.print(f"[SCANNING] Resuming folder: {local_path.name}")
                    self.send_folder_progress(root_folder_name, 0, 0, depth=depth, subfolder_path=None,
                                             total_scanned=total_items_processed, total_to_download=len(files_to_download))
                else:
                    # Normal case - we have a root folder, show subfolder progress
                    self.send_folder_progress(root_folder_name, folder_items_scanned, folder_files_to_download, depth=depth, subfolder_path=current_subfolder,
                                             total_scanned=total_items_processed, total_to_download=len(files_to_download))

            # Handle pagination - Microsoft Graph API returns max 200 items per page
            current_url = url
            page_count = 0

            while current_url:
                page_count += 1

                response = make_api_request(current_url)
                if response is None or response.status_code != 200:
                    return

                # Show connection success on first response
                if not connection_established:
                    builtins.print("[STARTUP] Connected to OneDrive!")
                    connection_established = True

                data = response.json()
                items = data.get('value', [])

                # Check for next page
                next_link = data.get('@odata.nextLink')

                if page_count > 1:
                    builtins.print(f"  {'  ' * depth}Page {page_count}: Processing {len(items)} more items in {local_path.name or 'root'}...")

                for item in items:
                    total_items_processed += 1
                    folder_items_scanned += 1  # Track per-folder count
                    name = item['name']
                    item_id = item['id']

                    if 'folder' in item:
                        # Before recursing, send folder progress update for current folder
                        # Use local_path.name directly instead of current_subfolder to avoid stale values
                        # after returning from recursive calls
                        if root_folder_name:
                            subfolder_to_send = local_path.name if depth >= 2 else None
                            self.send_folder_progress(root_folder_name, folder_items_scanned, folder_files_to_download, depth=depth, subfolder_path=subfolder_to_send,
                                                     total_scanned=total_items_processed, total_to_download=len(files_to_download))

                        # Add folder to queue (instead of recursing immediately)
                        new_local_path = local_path / name
                        new_local_path.mkdir(exist_ok=True, parents=True)
                        children_url = f"https://graph.microsoft.com/v1.0/me/drive/items/{item_id}/children"
                        folders_to_scan.append((children_url, str(new_local_path), depth + 1))
                    else:
                        # It's a file
                        ext = Path(name).suffix.lower()
                        should_include = False

                        if include_all:
                            should_include = True
                        elif include_docs and ext in doc_extensions:
                            should_include = True
                        elif include_pics and ext in pic_extensions:
                            should_include = True
                        elif include_videos and ext in video_extensions:
                            should_include = True

                        if should_include:
                            scanned_files += 1
                            file_size = item.get('size', 0)
                            file_path = local_path / name

                            # Check if we need to download this file
                            if self.should_download_file(item_id, file_size, file_path):
                                total_size_bytes += file_size
                                folder_files_to_download += 1  # Track per-folder to-download count
                                files_to_download.append({
                                    'item': item,
                                    'local_path': local_path,
                                    'depth': depth,
                                    'backup_root': backup_root
                                })
                            else:
                                skipped_files += 1

                    # Send per-folder progress update every 10 items for real-time UI feedback
                    # Use local_path.name directly instead of current_subfolder to avoid stale values
                    if root_folder_name and folder_items_scanned % 10 == 0:
                        subfolder_to_send = local_path.name if depth >= 2 else None
                        self.send_folder_progress(root_folder_name, folder_items_scanned, folder_files_to_download, depth=depth, subfolder_path=subfolder_to_send,
                                                 total_scanned=total_items_processed, total_to_download=len(files_to_download))

                    # Show progress every 100 matching files, OR every 200 total items, OR every 5 seconds
                    current_time = time.time()
                    should_show_progress = (
                        (scanned_files > 0 and scanned_files % 100 == 0) or
                        (total_items_processed % 200 == 0) or
                        (current_time - last_progress_time >= 5)
                    )

                    if should_show_progress and (scanned_files > 0 or total_items_processed > 0):
                        last_progress_time = current_time
                        builtins.print(f"  Scanned: {total_items_processed} items ({scanned_files} match), Need to download: {len(files_to_download)} ({self.format_size(total_size_bytes)})")
                        # Send progress via callback
                        self.send_scan_progress(total_items_processed, scanned_files, total_size_bytes, len(files_to_download))

                    # Save scan progress periodically (every 10 seconds)
                    if current_time - last_save_time >= 10:
                        save_scan_progress()

                    # Check for stop signal
                    if self.should_stop:
                        # Save remaining folders so scan can resume
                        pending_urls = [(u, p, d) for u, p, d in folders_to_scan]
                        save_scan_progress(is_partial=True, pending_urls=pending_urls)
                        return

                # Move to next page if it exists
                current_url = next_link

                # Check for stop signal between pages
                if self.should_stop:
                    # Save remaining folders so scan can resume
                    pending_urls = [(u, p, d) for u, p, d in folders_to_scan]
                    save_scan_progress(is_partial=True, pending_urls=pending_urls)
                    return

            # Mark this folder as fully scanned (only if we processed all pages without stopping)
            if folder_id and not self.should_stop:
                scanned_folder_ids.add(folder_id)

        def process_folder_queue():
            """Process the folder queue, checking for early download signal between folders"""
            nonlocal folders_to_scan, root_folder_name

            while folders_to_scan:
                # Check for early download signal BEFORE starting a new folder
                if self.start_download_early:
                    # Save remaining folders for later resume
                    pending_urls = [(url, path, depth) for url, path, depth in folders_to_scan]
                    builtins.print(f"\n📥 Download Now requested - stopping scan with {len(pending_urls)} folders remaining")
                    save_scan_progress(is_partial=True, pending_urls=pending_urls)
                    return 'early_download'

                # Check for stop signal
                if self.should_stop:
                    # Save remaining folders so scan can resume where it left off
                    pending_urls = [(url, path, depth) for url, path, depth in folders_to_scan]
                    save_scan_progress(is_partial=True, pending_urls=pending_urls)
                    return 'stopped'

                # Get next folder from queue
                url, local_path_str, depth = folders_to_scan.pop(0)
                local_path = Path(local_path_str)

                # Reset root_folder_name when moving to a new independent folder branch
                # This ensures resumed folders at depth > 1 get their own log entries
                if depth <= 2:
                    root_folder_name = None

                # Scan this folder (will add subfolders to the queue)
                scan_folder(url, local_path, depth)

            return 'complete'

        # If resuming a partial scan, load pending folders into the queue
        if pending_folder_urls:
            builtins.print(f"✓ Loading {len(pending_folder_urls)} pending folders from previous partial scan...")
            for item in pending_folder_urls:
                # Handle both old format (just url) and new format (url, path, depth tuple)
                if isinstance(item, (list, tuple)) and len(item) >= 3:
                    folders_to_scan.append((item[0], item[1], item[2]))
                else:
                    # Old format - skip (we don't have enough info)
                    builtins.print(f"  ⚠️  Skipping old-format pending folder entry")

        # Start scanning the root folder first
        scan_folder(graph_url, backup_root)

        # Process remaining folders in the queue
        scan_result = process_folder_queue()

        # Handle early download request
        if scan_result == 'early_download':
            builtins.print(f"\n✓ Partial scan complete!")
            builtins.print(f"  Folders scanned: {len(scanned_folder_ids)}")
            builtins.print(f"  Files to download: {len(files_to_download)}")
            builtins.print(f"  Size to download: {self.format_size(total_size_bytes)}")
            builtins.print(f"  Folders remaining: {len(folders_to_scan)} (will scan on resume)")
            if self.progress_callback:
                self.progress_callback('early_download', {
                    'message': f'Starting download of {len(files_to_download)} files...',
                    'files_found': len(files_to_download),
                    'folders_remaining': len(folders_to_scan)
                })
            # Don't return - continue to download phase with the files we have

        # Check if stop was requested during scanning
        elif self.should_stop:
            # Save remaining folders so scan can resume where it left off
            pending_urls = [(u, p, d) for u, p, d in folders_to_scan]
            save_scan_progress(is_partial=True, pending_urls=pending_urls)
            builtins.print(f"\n⏸️ Scan stopped by user")
            builtins.print(f"  Progress saved: {len(scanned_folder_ids)} folders scanned, {len(files_to_download)} files found")
            # Note: Don't send 'paused' here - backend.py already sends it in handle_stop_backup
            # Sending it again would cause setPausedUI to be called twice, hiding the Download Now button
            if self.progress_callback:
                self.progress_callback('log', {
                    'type': 'info',
                    'message': f'Scan stopped. Progress saved: {len(scanned_folder_ids)} folders, {len(files_to_download)} files found',
                    'icon': '⏸️'
                })
            return False

        else:
            # Full scan completed - clear scan progress from file (keep only downloaded_files for download resume)
            builtins.print(f"\n\n✓ Scan complete!")
            builtins.print(f"  Total files found: {scanned_files}")
            builtins.print(f"  Files to download: {len(files_to_download)}")
            builtins.print(f"  Files skipped (unchanged): {skipped_files}")
            builtins.print(f"  Size to download: {self.format_size(total_size_bytes)}\n")

        # Save scan state (either partial or complete)
        is_partial_scan = scan_result == 'early_download'
        progress_data = {
            'downloaded_files': self.downloaded_files,
            'scanned_folder_ids': list(scanned_folder_ids) if is_partial_scan else [],
            'files_to_download': [] if not is_partial_scan else [],  # Will be reloaded from queue
            'scan_in_progress': False,
            'partial_scan': is_partial_scan,
            'pending_folder_urls': [(url, path, depth) for url, path, depth in folders_to_scan] if is_partial_scan else []
        }
        with open(self.progress_file, 'w') as f:
            json.dump(progress_data, f)

        # PHASE 2: Check disk space
        builtins.print("Phase 2: Checking available disk space...\n")
        
        has_space, available, required = self.check_disk_space(destination, total_size_bytes)
        
        builtins.print(f"  Available space: {self.format_size(available)}")
        builtins.print(f"  Required space: {self.format_size(required)} (including 10% buffer)")
        
        if not has_space:
            builtins.print(f"\nERROR: Insufficient disk space!")
            builtins.print(f"  Need: {self.format_size(required - available)} more")
            builtins.print(f"\nOptions:")
            builtins.print(f"  1. Free up space on {destination}")
            builtins.print(f"  2. Use a different destination drive")
            builtins.print(f"  3. Select fewer file types to backup")
            return False
        
        builtins.print(f"  Sufficient space available\n")
        
        if len(files_to_download) == 0:
            builtins.print("All files are up to date! No downloads needed.")
            return True

        # Check if user paused during scan - don't automatically start downloading
        if self.should_stop:
            builtins.print("\n⏸️ Scan complete but backup was paused. Downloads not started.")
            builtins.print(f"  {len(files_to_download)} files ready to download when you resume.")
            save_scan_progress()
            if self.progress_callback:
                self.progress_callback('paused', {
                    'message': f'Scan complete. {len(files_to_download)} files ready to download when you resume.'
                })
            return False

        # PHASE 3: Download files with multi-threading
        return self._run_download_phase(files_to_download, save_scan_progress, backup_root)
    
    def get_documents_and_pictures(self):
        """Find all documents and pictures in OneDrive"""
        if not self.onedrive_path:
            return [], []

        # Use class-level extension constants
        doc_extensions = self.DOC_EXTENSIONS
        pic_extensions = self.PIC_EXTENSIONS
        
        documents = []
        pictures = []
        
        builtins.print("Scanning OneDrive for files...")
        folder_count = 0
        skipped_online_only = 0
        
        for root, dirs, files in os.walk(self.onedrive_path):
            folder_count += 1
            if folder_count % 10 == 0:
                builtins.print(f"   Scanned {folder_count} folders, found {len(documents)} docs, {len(pictures)} pics...", end='\r')
            
            for file in files:
                file_path = Path(root) / file
                ext = file_path.suffix.lower()
                
                # Skip files that are online-only (0 bytes or have cloud icon attributes)
                try:
                    if file_path.stat().st_size == 0:
                        skipped_online_only += 1
                        continue
                except:
                    continue
                
                if ext in doc_extensions:
                    documents.append(file_path)
                elif ext in pic_extensions:
                    pictures.append(file_path)
        
        builtins.print(f"\n✓ Scan complete! Found {len(documents)} documents and {len(pictures)} pictures")
        if skipped_online_only > 0:
            builtins.print(f"⚠️  Skipped {skipped_online_only} online-only files (not downloaded locally)")
            builtins.print("   To backup these files, either:")
            builtins.print("   1. Download them in OneDrive first, or")
            builtins.print("   2. Use the online login method when running this script\n")
        else:
            builtins.print()
        return documents, pictures
    
    def backup_files(self, destination_drive, include_docs=True, include_pics=True):
        """Backup files to external drive"""
        if not self.onedrive_path:
            builtins.print("❌ OneDrive folder not found!")
            builtins.print("Please ensure OneDrive is installed and synced.")
            return False
        
        destination = Path(destination_drive)
        if not destination.exists():
            builtins.print(f"❌ Destination drive '{destination_drive}' not found!")
            return False
        
        # Create backup folder with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_root = destination / f"OneDrive_Backup_{timestamp}"
        backup_root.mkdir(exist_ok=True)
        
        builtins.print(f"\nOneDrive location: {self.onedrive_path}")
        builtins.print(f"Backup destination: {backup_root}\n")
        
        documents, pictures = self.get_documents_and_pictures()
        
        total_files = 0
        copied_files = 0
        failed_files = []
        
        # Backup documents
        if include_docs and documents:
            builtins.print(f"Backing up {len(documents)} documents...")
            docs_folder = backup_root / "Documents"
            docs_folder.mkdir(exist_ok=True)
            
            for idx, doc in enumerate(documents, 1):
                total_files += 1
                try:
                    relative_path = doc.relative_to(self.onedrive_path)
                    dest_file = docs_folder / relative_path
                    dest_file.parent.mkdir(parents=True, exist_ok=True)
                    
                    shutil.copy2(doc, dest_file)
                    copied_files += 1
                    self.backup_log.append({
                        'file': str(doc),
                        'destination': str(dest_file),
                        'status': 'success'
                    })
                    # Show progress every file
                    builtins.print(f"  [{idx}/{len(documents)}] ✓ {relative_path.name[:50]}", end='\r')
                except Exception as e:
                    failed_files.append((doc, str(e)))
                    self.backup_log.append({
                        'file': str(doc),
                        'status': 'failed',
                        'error': str(e)
                    })
                    builtins.print(f"  [{idx}/{len(documents)}] ✗ {doc.name}: {e}")
            builtins.print()  # New line after progress
        
        # Backup pictures
        if include_pics and pictures:
            builtins.print(f"\nBacking up {len(pictures)} pictures...")
            pics_folder = backup_root / "Pictures"
            pics_folder.mkdir(exist_ok=True)
            
            for idx, pic in enumerate(pictures, 1):
                total_files += 1
                try:
                    relative_path = pic.relative_to(self.onedrive_path)
                    dest_file = pics_folder / relative_path
                    dest_file.parent.mkdir(parents=True, exist_ok=True)
                    
                    shutil.copy2(pic, dest_file)
                    copied_files += 1
                    self.backup_log.append({
                        'file': str(pic),
                        'destination': str(dest_file),
                        'status': 'success'
                    })
                    # Show progress every file
                    builtins.print(f"  [{idx}/{len(pictures)}] ✓ {relative_path.name[:50]}", end='\r')
                except Exception as e:
                    failed_files.append((pic, str(e)))
                    self.backup_log.append({
                        'file': str(pic),
                        'status': 'failed',
                        'error': str(e)
                    })
                    builtins.print(f"  [{idx}/{len(pictures)}] ✗ {pic.name}: {e}")
            builtins.print()  # New line after progress
        
        # Save backup log
        log_file = backup_root / "backup_log.json"
        with open(log_file, 'w') as f:
            json.dump({
                'timestamp': timestamp,
                'total_files': total_files,
                'copied_files': copied_files,
                'failed_files': len(failed_files),
                'files': self.backup_log
            }, f, indent=2)
        
        # Print summary
        builtins.print("\n" + "="*50)
        builtins.print("BACKUP SUMMARY")
        builtins.print("="*50)
        builtins.print(f"Total files found: {total_files}")
        builtins.print(f"Successfully copied: {copied_files}")
        builtins.print(f"Failed: {len(failed_files)}")
        builtins.print(f"Backup location: {backup_root}")
        builtins.print(f"Log file: {log_file}")
        
        if failed_files:
            builtins.print("\n⚠️  Failed files:")
            for file, error in failed_files[:10]:
                builtins.print(f"  - {file.name}: {error}")
            if len(failed_files) > 10:
                builtins.print(f"  ... and {len(failed_files) - 10} more")
        
        return True

def main():
    builtins.print("="*50)
    builtins.print("OneDrive Backup Tool - Enhanced Edition")
    builtins.print("="*50)
    builtins.print("\nFeatures:")
    builtins.print("  ✓ Multi-threaded downloads (3x faster)")
    builtins.print("  ✓ Disk space verification")
    builtins.print("  ✓ File integrity verification")
    builtins.print("  ✓ Incremental backups (skip unchanged files)")
    builtins.print("  ✓ Resume capability")
    
    backup = OneDriveBackup()
    
    # Always give user the choice
    if backup.onedrive_path:
        builtins.print(f"\n✓ Local OneDrive found at: {backup.onedrive_path}")
        builtins.print("\n⚠️  Note: Local OneDrive may contain Files On-Demand (0 KB placeholders)")
        builtins.print("\nHow would you like to backup?")
        builtins.print("1. Use local OneDrive folder (only backs up downloaded files)")
        builtins.print("2. Login to OneDrive online and download all files from cloud")
        builtins.print("3. Exit")
        
        choice = input("\nEnter choice (1-3): ").strip()
        
        if choice == '2':
            if not backup.login_to_onedrive_api():
                builtins.print("❌ Login failed. Exiting.")
                return
        elif choice == '3':
            return
        # choice == '1' continues with local folder
    else:
        builtins.print("\n⚠️  Could not locate local OneDrive folder.")
        builtins.print("\nOptions:")
        builtins.print("1. Enter OneDrive path manually")
        builtins.print("2. Login to OneDrive online and download files")
        builtins.print("3. Exit")
        
        choice = input("\nEnter choice (1-3): ").strip()
        
        if choice == '1':
            manual_path = input("Enter your OneDrive path: ").strip()
            backup.onedrive_path = Path(manual_path)
            
            if not backup.onedrive_path.exists():
                builtins.print("❌ Invalid path. Trying online login...")
                choice = '2'
        
        if choice == '2':
            if not backup.login_to_onedrive_api():
                builtins.print("❌ Login failed. Exiting.")
                return
        elif choice == '3':
            return
    
    # Get destination drive
    builtins.print("\nEnter the path to your external drive (e.g., E:, /media/backup, etc.):")
    destination = input("> ").strip()
    
    destination_path = Path(destination)
    if not destination_path.exists():
        builtins.print(f"❌ Destination drive '{destination}' not found!")
        return
    
    # Check for existing backups and ask user BEFORE asking what to backup
    existing_backups = sorted([d for d in destination_path.glob("OneDrive_Backup_*") if d.is_dir()], 
                             key=lambda x: x.stat().st_mtime, reverse=True)
    
    resume_backup_path = None
    if existing_backups:
        builtins.print("\nFound existing backup(s):")
        for i, backup_dir in enumerate(existing_backups[:5], 1):
            progress_file = backup_dir / ".progress.json"
            metadata_file = backup_dir / ".backup_metadata.json"
            
            if progress_file.exists():
                try:
                    with open(progress_file, 'r') as f:
                        progress_data = json.load(f)
                        file_count = len(progress_data.get('downloaded_files', {}))
                    builtins.print(f"  {i}. {backup_dir.name} ({file_count} files already downloaded) - INCOMPLETE")
                except:
                    builtins.print(f"  {i}. {backup_dir.name} (progress file exists)")
            elif metadata_file.exists():
                try:
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                        file_count = len(metadata.get('files', {}))
                    builtins.print(f"  {i}. {backup_dir.name} ({file_count} files) - COMPLETE")
                except:
                    builtins.print(f"  {i}. {backup_dir.name}")
            else:
                builtins.print(f"  {i}. {backup_dir.name}")
        
        builtins.print(f"  {len(existing_backups) + 1}. Start a new backup")
        
        choice = input(f"\nResume which backup? (1-{len(existing_backups) + 1}): ").strip()
        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(existing_backups):
                resume_backup_path = existing_backups[choice_num - 1]
                builtins.print(f"\n✓ Will resume: {resume_backup_path.name}")
            else:
                builtins.print(f"\n✓ Will start a new backup")
        except (ValueError, IndexError):
            builtins.print(f"\n✓ Will start a new backup")
    else:
        builtins.print("\n✓ No existing backups found - will start new backup")
    
    # Ask what to backup
    builtins.print("\nWhat would you like to backup?")
    builtins.print("1. Documents only")
    builtins.print("2. Pictures only")
    builtins.print("3. Videos only")
    builtins.print("4. Documents and Pictures")
    builtins.print("5. Documents and Videos")
    builtins.print("6. Pictures and Videos")
    builtins.print("7. Documents, Pictures, and Videos")
    builtins.print("8. All Files (everything, including audio, web pages, etc.)")
    choice = input("Enter choice (1-8): ").strip()
    
    include_all = choice == '8'
    include_docs = choice in ['1', '4', '5', '7']
    include_pics = choice in ['2', '4', '6', '7']
    include_videos = choice in ['3', '5', '6', '7']
    
    builtins.print("\nStarting backup...")
    
    # Backup loop - allows retrying failed files
    while True:
        if backup.use_api:
            result = backup.download_from_api(destination, include_docs, include_pics, include_videos, include_all, resume_backup_path)
        else:
            result = backup.backup_files(destination, include_docs, include_pics)
            result = {'success': True, 'failed_count': 0, 'downloaded_count': 0}  # Local backup doesn't track failures the same way
        
        # Check if any files failed
        if isinstance(result, dict) and result.get('failed_count', 0) > 0:
            builtins.print(f"\n{'='*50}")
            builtins.print(f"⚠️  {result['failed_count']} files failed to download.")
            builtins.print(f"{'='*50}")
            retry = input(f"\nRetry failed files now? (y/n): ").strip().lower()
            
            if retry == 'y' or retry == 'yes':
                builtins.print(f"\nRetrying {result['failed_count']} failed files...")
                builtins.print(f"Note: Successfully downloaded files will be skipped.\n")
                # Keep the same resume_backup_path to continue in same folder
                continue
            else:
                builtins.print(f"\nTo retry later, run the script again and choose the same backup.")
                break
        else:
            # No failures or user cancelled
            break
    
    builtins.print("\nBackup complete!")

if __name__ == "__main__":
    main()
