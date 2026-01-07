// preload.js - Secure bridge between UI and Node.js
// v2.1.0: Added SimpleAuth (hosted auth) APIs
const { contextBridge, ipcRenderer } = require('electron');

// Expose safe APIs to the renderer process
contextBridge.exposeInMainWorld('electronAPI', {
    // ===== NEW: SimpleAuth (Hosted Authentication) =====
    // Check if SimpleAuth is available and user's login status
    checkSimpleAuth: () => ipcRenderer.invoke('check-simple-auth'),
    
    // Login with Microsoft (opens browser)
    simpleAuthLogin: () => ipcRenderer.invoke('simple-auth-login'),
    
    // Logout from SimpleAuth
    simpleAuthLogout: () => ipcRenderer.invoke('simple-auth-logout'),
    
    // ===== Legacy Authentication =====
    // Authenticate with app credentials (Azure setup required)
    authenticate: (authData) => ipcRenderer.invoke('authenticate', authData),
    
    // ===== File System =====
    browseFolder: () => ipcRenderer.invoke('browse-folder'),
    
    // ===== Backup Operations =====
    startBackup: (config) => ipcRenderer.invoke('start-backup', config),
    getHistory: (destination) => ipcRenderer.invoke('get-history', destination),
    checkDiskSpace: (destination) => ipcRenderer.invoke('check-disk-space', destination),
    
    // ===== Credential Management (Secure Storage) =====
    saveCredentials: (credentials) => ipcRenderer.invoke('save-credentials', credentials),
    loadCredentials: () => ipcRenderer.invoke('load-credentials'),
    deleteCredentials: () => ipcRenderer.invoke('delete-credentials'),
    
    // ===== Utilities =====
    // Open external URL in default browser
    openExternal: (url) => ipcRenderer.invoke('open-external', url),
    
    // Get app version
    getVersion: () => ipcRenderer.invoke('get-version'),
    
    // ===== Event Listeners =====
    // Progress updates from Python
    onProgress: (callback) => {
        ipcRenderer.on('python-output', (event, data) => {
            try {
                const parsed = JSON.parse(data);
                if (parsed.type === 'progress' || parsed.progressType) {
                    callback(parsed);
                }
            } catch (e) {
                // Not JSON progress, might be plain text
                // Try to handle plain text output too
                if (data && typeof data === 'string') {
                    callback({
                        type: 'progress',
                        progressType: 'log',
                        data: {
                            type: 'info',
                            message: data.trim(),
                            icon: 'ℹ️'
                        }
                    });
                }
            }
        });
    },
    
    // Error messages from Python
    onError: (callback) => {
        ipcRenderer.on('python-error', (event, data) => {
            callback(data);
        });
    },
    
    // General Python output
    onPythonOutput: (callback) => {
        ipcRenderer.on('python-output', (event, data) => {
            callback(data);
        });
    },
    
    // ===== Platform Info =====
    platform: process.platform,
});
