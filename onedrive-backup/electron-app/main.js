// main.js - Electron Main Process
// v2.1.0: Added SimpleAuth (hosted auth) support
const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow;
let pythonProcess;
let simpleAuthAvailable = false;

// Create the main application window
function createWindow() {
    mainWindow = new BrowserWindow({
        width: 900,
        height: 700,
        minWidth: 800,
        minHeight: 600,
        titleBarStyle: 'hiddenInset', // macOS style
        backgroundColor: '#F5F5F7',
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            enableRemoteModule: false,
            preload: path.join(__dirname, 'preload.js')
        },
        show: false // Don't show until ready
    });

    // Load the UI
    mainWindow.loadFile('ui.html');

    // Show window when ready (prevents flash)
    mainWindow.once('ready-to-show', () => {
        mainWindow.show();
    });

    // Handle window close
    mainWindow.on('closed', () => {
        mainWindow = null;
    });

    // Open DevTools in development
    if (process.env.NODE_ENV === 'development') {
        mainWindow.webContents.openDevTools();
    }
}

// Start Python backend
function startPythonBackend() {
    const pythonScript = path.join(__dirname, 'backend.py');
    
    // Determine Python command based on platform
    const pythonCommand = process.platform === 'win32' ? 'python' : 'python3';
    
    pythonProcess = spawn(pythonCommand, [pythonScript], {
        cwd: __dirname // Set working directory to app directory
    });

    pythonProcess.stdout.on('data', (data) => {
        const output = data.toString();
        console.log(`Python: ${output}`);
        
        // Check for ready message with simpleAuthAvailable flag
        try {
            const parsed = JSON.parse(output.trim());
            if (parsed.type === 'ready' && parsed.simpleAuthAvailable !== undefined) {
                simpleAuthAvailable = parsed.simpleAuthAvailable;
                console.log(`SimpleAuth available: ${simpleAuthAvailable}`);
            }
        } catch (e) {
            // Not JSON, ignore
        }
        
        // Send output to renderer process
        if (mainWindow) {
            mainWindow.webContents.send('python-output', output);
        }
    });

    pythonProcess.stderr.on('data', (data) => {
        console.error(`Python Error: ${data}`);
        if (mainWindow) {
            mainWindow.webContents.send('python-error', data.toString());
        }
    });

    pythonProcess.on('close', (code) => {
        console.log(`Python process exited with code ${code}`);
    });
}

// Stop Python backend
function stopPythonBackend() {
    if (pythonProcess) {
        pythonProcess.kill();
        pythonProcess = null;
    }
}

// App lifecycle events
app.whenReady().then(() => {
    createWindow();
    startPythonBackend();

    app.on('activate', () => {
        // On macOS, re-create window when dock icon is clicked
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        }
    });
});

app.on('window-all-closed', () => {
    // On macOS, apps stay open until Cmd+Q
    if (process.platform !== 'darwin') {
        stopPythonBackend();
        app.quit();
    }
});

app.on('before-quit', () => {
    stopPythonBackend();
});

// Helper function to send request to Python and wait for response
function sendPythonRequest(action, data, responseAction, timeout = 60000) {
    return new Promise((resolve, reject) => {
        const request = JSON.stringify({ action, data }) + '\n';
        
        pythonProcess.stdin.write(request);
        
        const responseHandler = (output) => {
            try {
                const response = JSON.parse(output.toString().trim());
                if (response.action === responseAction) {
                    pythonProcess.stdout.removeListener('data', responseHandler);
                    resolve(response);
                }
            } catch (e) {
                // Not JSON or not our response, ignore
            }
        };
        
        pythonProcess.stdout.on('data', responseHandler);
        
        setTimeout(() => {
            pythonProcess.stdout.removeListener('data', responseHandler);
            reject(new Error(`${action} timeout`));
        }, timeout);
    });
}

// IPC Handlers - Communication between UI and Python

// Check SimpleAuth availability and login status
ipcMain.handle('check-simple-auth', async () => {
    try {
        return await sendPythonRequest('check-simple-auth', {}, 'simple-auth-status', 5000);
    } catch (error) {
        return { available: false, loggedIn: false, error: error.message };
    }
});

// Login with SimpleAuth (hosted auth)
ipcMain.handle('simple-auth-login', async () => {
    try {
        return await sendPythonRequest('authenticate', { method: 'simple' }, 'authenticate', 300000); // 5 min timeout for browser auth
    } catch (error) {
        return { success: false, error: error.message };
    }
});

// Logout from SimpleAuth
ipcMain.handle('simple-auth-logout', async () => {
    try {
        return await sendPythonRequest('simple-auth-logout', {}, 'logout', 5000);
    } catch (error) {
        return { success: false, error: error.message };
    }
});

// Authenticate with OneDrive (legacy methods)
ipcMain.handle('authenticate', async (event, authData) => {
    try {
        return await sendPythonRequest('authenticate', authData, 'authenticate', 60000);
    } catch (error) {
        return { success: false, error: error.message };
    }
});

// Browse for destination folder
ipcMain.handle('browse-folder', async () => {
    const result = await dialog.showOpenDialog(mainWindow, {
        properties: ['openDirectory'],
        title: 'Select Backup Destination'
    });
    
    if (!result.canceled && result.filePaths.length > 0) {
        return result.filePaths[0];
    }
    return null;
});

// Start backup
ipcMain.handle('start-backup', async (event, backupConfig) => {
    return new Promise((resolve, reject) => {
        const request = JSON.stringify({
            action: 'start-backup',
            data: backupConfig
        }) + '\n';
        
        pythonProcess.stdin.write(request);
        
        // Listen for completion (long timeout for large backups)
        const responseHandler = (data) => {
            try {
                const response = JSON.parse(data.toString().trim());
                if (response.action === 'backup-complete') {
                    pythonProcess.stdout.removeListener('data', responseHandler);
                    resolve(response);
                }
            } catch (e) {
                // Not JSON or not our response, ignore
            }
        };
        
        pythonProcess.stdout.on('data', responseHandler);
        
        // No timeout for backup - it can take hours
    });
});

// Get backup history
ipcMain.handle('get-history', async (event, destination) => {
    try {
        return await sendPythonRequest('get-history', { destination }, 'history', 5000);
    } catch (error) {
        return { success: false, backups: [], error: error.message };
    }
});

// Check disk space
ipcMain.handle('check-disk-space', async (event, destination) => {
    try {
        return await sendPythonRequest('check-disk-space', { destination }, 'disk-space', 5000);
    } catch (error) {
        return { success: false, error: error.message };
    }
});

// Open external URL (for help links, etc.)
ipcMain.handle('open-external', async (event, url) => {
    await shell.openExternal(url);
    return { success: true };
});

// Get app version
ipcMain.handle('get-version', async () => {
    return app.getVersion();
});

// Store credentials securely (uses OS keychain)
const keytar = require('keytar');
const SERVICE_NAME = 'OneDrive Backup Manager';

ipcMain.handle('save-credentials', async (event, credentials) => {
    try {
        await keytar.setPassword(SERVICE_NAME, 'client-id', credentials.clientId);
        await keytar.setPassword(SERVICE_NAME, 'client-secret', credentials.clientSecret);
        await keytar.setPassword(SERVICE_NAME, 'tenant-id', credentials.tenantId || 'common');
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('load-credentials', async () => {
    try {
        const clientId = await keytar.getPassword(SERVICE_NAME, 'client-id');
        const clientSecret = await keytar.getPassword(SERVICE_NAME, 'client-secret');
        const tenantId = await keytar.getPassword(SERVICE_NAME, 'tenant-id');
        
        return {
            success: true,
            credentials: { clientId, clientSecret, tenantId }
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

ipcMain.handle('delete-credentials', async () => {
    try {
        await keytar.deletePassword(SERVICE_NAME, 'client-id');
        await keytar.deletePassword(SERVICE_NAME, 'client-secret');
        await keytar.deletePassword(SERVICE_NAME, 'tenant-id');
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
});
