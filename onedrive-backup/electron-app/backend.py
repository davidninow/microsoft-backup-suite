#!/usr/bin/env python3
"""
backend.py - Python backend for Electron app
Communicates with Electron via stdin/stdout using JSON messages

v2.1.0: Added hosted authentication via SimpleAuth
"""

import sys
import json
import threading
from pathlib import Path
from datetime import datetime
from onedrive_backup_enhanced import OneDriveBackup

# Import SimpleAuth for hosted authentication
try:
    from auth_client import SimpleAuth
    SIMPLE_AUTH_AVAILABLE = True
except ImportError:
    SIMPLE_AUTH_AVAILABLE = False
    print("Warning: auth_client.py not found. Hosted auth will be unavailable.", file=sys.stderr)

# Import the backup class
backup = OneDriveBackup()

# Global SimpleAuth instance
simple_auth = None

def send_message(message):
    """Send JSON message to Electron main process"""
    sys.stdout.write(json.dumps(message) + '\n')
    sys.stdout.flush()

def send_progress(progress_type, data):
    """Send progress update to UI"""
    send_message({
        'type': 'progress',
        'progressType': progress_type,
        'data': data,
        'timestamp': datetime.now().isoformat()
    })

def handle_check_simple_auth(data):
    """Check if SimpleAuth (hosted auth) is available and if user is logged in"""
    global simple_auth
    
    if not SIMPLE_AUTH_AVAILABLE:
        send_message({
            'action': 'simple-auth-status',
            'available': False,
            'loggedIn': False,
            'message': 'Hosted auth not available'
        })
        return
    
    try:
        if simple_auth is None:
            simple_auth = SimpleAuth()
        
        logged_in = simple_auth.is_logged_in()
        
        send_message({
            'action': 'simple-auth-status',
            'available': True,
            'loggedIn': logged_in,
            'message': 'Logged in' if logged_in else 'Not logged in'
        })
    except Exception as e:
        send_message({
            'action': 'simple-auth-status',
            'available': False,
            'loggedIn': False,
            'message': str(e)
        })

def handle_simple_auth_login(data):
    """Handle login via hosted auth service (SimpleAuth)"""
    global simple_auth, backup
    
    if not SIMPLE_AUTH_AVAILABLE:
        send_message({
            'action': 'authenticate',
            'success': False,
            'message': 'Hosted auth not available. Please use Azure app credentials.'
        })
        return
    
    try:
        if simple_auth is None:
            simple_auth = SimpleAuth()
        
        send_progress('log', {
            'type': 'info',
            'message': 'Starting Microsoft login...',
            'icon': '🔐'
        })
        
        # Check if already logged in, try refresh first
        if simple_auth.is_logged_in():
            send_progress('log', {
                'type': 'info',
                'message': 'Existing session found, refreshing...',
                'icon': '🔄'
            })
            if simple_auth.refresh_token():
                # Transfer token to backup object
                backup.access_token = simple_auth.access_token
                backup.use_api = True
                
                send_message({
                    'action': 'authenticate',
                    'success': True,
                    'method': 'simple',
                    'message': 'Logged in with existing session'
                })
                return
        
        # Need fresh login - this opens browser
        send_progress('log', {
            'type': 'info',
            'message': 'Opening browser for Microsoft login...',
            'icon': '🌐'
        })
        
        success = simple_auth.login()
        
        if success:
            # Transfer token to backup object
            backup.access_token = simple_auth.access_token
            backup.use_api = True
            
            # Set up a custom refresh function that uses SimpleAuth
            original_refresh = backup.refresh_access_token
            def simple_auth_refresh():
                if simple_auth.refresh_token():
                    backup.access_token = simple_auth.access_token
                    return True
                return original_refresh()
            backup.refresh_access_token = simple_auth_refresh
            
            send_message({
                'action': 'authenticate',
                'success': True,
                'method': 'simple',
                'message': 'Successfully logged in with Microsoft!'
            })
        else:
            send_message({
                'action': 'authenticate',
                'success': False,
                'message': 'Login failed or was cancelled'
            })
    
    except Exception as e:
        send_message({
            'action': 'authenticate',
            'success': False,
            'message': str(e)
        })

def handle_simple_auth_logout(data):
    """Handle logout from hosted auth"""
    global simple_auth, backup
    
    if simple_auth:
        simple_auth.logout()
        simple_auth = None
    
    backup.access_token = None
    backup.use_api = False
    
    send_message({
        'action': 'logout',
        'success': True,
        'message': 'Logged out successfully'
    })

def handle_authenticate(data):
    """Handle authentication request"""
    global simple_auth, backup
    
    try:
        auth_method = data.get('method')
        
        # NEW: Handle SimpleAuth (hosted auth)
        if auth_method == 'simple':
            handle_simple_auth_login(data)
            return
        
        if auth_method == 'app':
            backup.client_id = data.get('clientId')
            backup.client_secret = data.get('clientSecret')
            backup.tenant_id = data.get('tenantId', 'common')
            
            success = backup.delegated_auth_flow()
            
            send_message({
                'action': 'authenticate',
                'success': success,
                'method': 'app',
                'message': 'Authentication successful' if success else 'Authentication failed'
            })
        
        elif auth_method == 'device':
            success = backup.device_code_auth()
            
            send_message({
                'action': 'authenticate',
                'success': success,
                'method': 'device',
                'message': 'Authentication successful' if success else 'Authentication failed'
            })
        
        elif auth_method == 'local':
            if backup.onedrive_path:
                send_message({
                    'action': 'authenticate',
                    'success': True,
                    'method': 'local',
                    'message': f'Using local OneDrive: {backup.onedrive_path}'
                })
            else:
                send_message({
                    'action': 'authenticate',
                    'success': False,
                    'message': 'Local OneDrive folder not found'
                })
    
    except Exception as e:
        send_message({
            'action': 'authenticate',
            'success': False,
            'message': str(e)
        })

def handle_start_backup(data):
    """Handle backup start request with enhanced progress tracking"""
    try:
        destination = data.get('destination')
        include_docs = data.get('includeDocs', True)
        include_pics = data.get('includePics', True)
        include_videos = data.get('includeVideos', True)
        include_all = data.get('includeAll', False)
        resume_path = data.get('resumePath')  # Optional: path to resume backup
        
        # Store original print function
        import builtins
        original_print = builtins.print
        
        def enhanced_print(*args, **kwargs):
            """Intercept print statements and send as progress updates to UI"""
            message = ' '.join(str(arg) for arg in args)
            
            # Determine log type and icon based on message content
            log_type = 'info'
            icon = 'ℹ️'
            
            # Success indicators
            if any(indicator in message for indicator in ['✅', '✓', 'success', 'complete', 'Successfully']):
                log_type = 'success'
                icon = '✓'
            # Error indicators
            elif any(indicator in message for indicator in ['❌', '✗', 'error', 'failed', 'Error', 'Failed']):
                log_type = 'error'
                icon = '✗'
            # Warning indicators
            elif any(indicator in message for indicator in ['⚠️', 'warning', 'retry', 'Retry', 'timeout', 'Timeout']):
                log_type = 'warning'
                icon = '⚠️'
            # Download indicators
            elif any(indicator in message for indicator in ['📥', 'download', 'Download', 'Downloading']):
                log_type = 'download'
                icon = '📥'
            # Verify indicators
            elif any(indicator in message for indicator in ['🔒', 'verify', 'Verify', 'hash', 'SHA']):
                log_type = 'verify'
                icon = '🔒'
            # Phase indicators
            elif 'Phase' in message or 'phase' in message:
                log_type = 'phase'
                icon = '📊'
            # Scanning indicators
            elif any(indicator in message for indicator in ['🔍', 'scan', 'Scan']):
                log_type = 'info'
                icon = '🔍'
            # Token refresh indicators
            elif any(indicator in message for indicator in ['🔄', 'refresh', 'Refresh', 'token']):
                log_type = 'info'
                icon = '🔄'
            
            # Send to UI
            send_progress('log', {
                'type': log_type,
                'message': message,
                'icon': icon
            })
            
            # Also call original print for console debugging
            original_print(*args, **kwargs)
        
        # Start backup in background thread
        def run_backup():
            try:
                # Replace print with enhanced version
                builtins.print = enhanced_print
                
                send_progress('phase', {'phase': 1, 'message': 'Starting backup...'})
                send_progress('started', {'message': 'Backup started'})
                
                print("🔐 Authenticating with OneDrive...")
                
                if backup.use_api:
                    print("📊 Phase 1: Scanning OneDrive folders...")
                    send_progress('phase', {'phase': 1, 'message': 'Scanning OneDrive...'})
                    
                    # Convert resume_path to Path if provided
                    resume_backup_path = Path(resume_path) if resume_path else None
                    
                    result = backup.download_from_api(
                        destination,
                        include_docs,
                        include_pics,
                        include_videos,
                        include_all,
                        resume_backup_path
                    )
                    
                    # Handle new dict return type from v2.0
                    if isinstance(result, dict):
                        success = result.get('success', False)
                        failed_count = result.get('failed_count', 0)
                        downloaded_count = result.get('downloaded_count', 0)
                    else:
                        success = result
                        failed_count = 0
                        downloaded_count = 0
                else:
                    success = backup.backup_files(
                        destination,
                        include_docs,
                        include_pics
                    )
                    failed_count = 0
                    downloaded_count = 0
                
                # Restore original print
                builtins.print = original_print
                
                if success:
                    send_progress('complete', {
                        'message': 'Backup completed successfully!',
                        'failedCount': failed_count,
                        'downloadedCount': downloaded_count
                    })
                
                send_message({
                    'action': 'backup-complete',
                    'success': success,
                    'failedCount': failed_count,
                    'downloadedCount': downloaded_count,
                    'message': 'Backup completed successfully' if success else 'Backup failed'
                })
            
            except Exception as e:
                # Restore original print on error
                builtins.print = original_print
                
                send_progress('log', {
                    'type': 'error',
                    'message': f'Backup error: {str(e)}',
                    'icon': '✗'
                })
                
                send_message({
                    'action': 'backup-complete',
                    'success': False,
                    'message': str(e)
                })
        
        backup_thread = threading.Thread(target=run_backup)
        backup_thread.daemon = True
        backup_thread.start()
        
    except Exception as e:
        send_message({
            'action': 'backup-complete',
            'success': False,
            'message': str(e)
        })

def handle_get_history(data):
    """Get backup history from destination"""
    try:
        destination = Path(data.get('destination', ''))
        
        if not destination.exists():
            send_message({
                'action': 'history',
                'success': False,
                'backups': []
            })
            return
        
        # Find all backup folders
        backups = []
        for backup_dir in sorted(destination.glob('OneDrive_Backup_*'), 
                                key=lambda x: x.stat().st_mtime, reverse=True):
            if backup_dir.is_dir():
                # Get backup info
                metadata_file = backup_dir / '.backup_metadata.json'
                progress_file = backup_dir / '.progress.json'
                
                file_count = 0
                size = 0
                status = 'complete'
                
                if metadata_file.exists():
                    try:
                        with open(metadata_file, 'r') as f:
                            metadata = json.load(f)
                            file_count = len(metadata.get('files', {}))
                    except:
                        pass
                
                if progress_file.exists():
                    status = 'incomplete'
                    try:
                        with open(progress_file, 'r') as f:
                            progress = json.load(f)
                            file_count = len(progress.get('downloaded_files', {}))
                    except:
                        pass
                
                # Calculate total size
                try:
                    size = sum(f.stat().st_size for f in backup_dir.rglob('*') if f.is_file())
                except:
                    pass
                
                backups.append({
                    'name': backup_dir.name,
                    'path': str(backup_dir),
                    'date': backup_dir.stat().st_mtime,
                    'fileCount': file_count,
                    'size': size,
                    'status': status
                })
        
        send_message({
            'action': 'history',
            'success': True,
            'backups': backups
        })
    
    except Exception as e:
        send_message({
            'action': 'history',
            'success': False,
            'backups': [],
            'error': str(e)
        })

def handle_check_disk_space(data):
    """Check available disk space"""
    try:
        destination = Path(data.get('destination', ''))
        
        if not destination.exists():
            send_message({
                'action': 'disk-space',
                'success': False,
                'message': 'Destination not found'
            })
            return
        
        import shutil
        stat = shutil.disk_usage(destination)
        
        send_message({
            'action': 'disk-space',
            'success': True,
            'available': stat.free,
            'total': stat.total,
            'used': stat.used
        })
    
    except Exception as e:
        send_message({
            'action': 'disk-space',
            'success': False,
            'message': str(e)
        })

def main():
    """Main loop - read JSON messages from stdin"""
    send_message({
        'type': 'ready',
        'message': 'Python backend ready',
        'simpleAuthAvailable': SIMPLE_AUTH_AVAILABLE
    })
    
    for line in sys.stdin:
        try:
            message = json.loads(line.strip())
            action = message.get('action')
            data = message.get('data', {})
            
            if action == 'authenticate':
                handle_authenticate(data)
            elif action == 'check-simple-auth':
                handle_check_simple_auth(data)
            elif action == 'simple-auth-login':
                handle_simple_auth_login(data)
            elif action == 'simple-auth-logout':
                handle_simple_auth_logout(data)
            elif action == 'start-backup':
                handle_start_backup(data)
            elif action == 'get-history':
                handle_get_history(data)
            elif action == 'check-disk-space':
                handle_check_disk_space(data)
            else:
                send_message({
                    'type': 'error',
                    'message': f'Unknown action: {action}'
                })
        
        except json.JSONDecodeError:
            send_message({
                'type': 'error',
                'message': 'Invalid JSON message'
            })
        except Exception as e:
            send_message({
                'type': 'error',
                'message': str(e)
            })

if __name__ == '__main__':
    main()
