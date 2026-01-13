# OneDrive Backup Tool

![Python](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

Breaking free from Microsoft is hard. MSFT does everything they can to lock you in. This Backup Tool is for OneDrive users with a lot of data on OneDrive, who want an easy way to download/export all that data at once but don't have space on their local machine to do so.

This privacy-first Python script will automatically backup your entire OneDrive (for personal accounts) to an external hard drive of your choice, and preserve your exact OneDrive folder structure.

## 🎉 What's New in v2.0

- ✅ No more 200-file limit - Downloads ALL files
- ✅ Token auto-refresh - Zero HTTP 401 errors
- ✅ 40GB+ file support - Handles huge files
- ✅ Failed files report - See exactly what failed
- ✅ Interactive retry - Retry without exiting

See full [CHANGELOG](https://github.com/davidninow/microsoft-backup-suite/blob/main/CHANGELOG.md)

## Features

- ✅ **Automatic authentication** via Microsoft Graph API
- ✅ **Preserves folder structure** exactly as in OneDrive
- ✅ **Auto-refreshing tokens** - can run for days/weeks without re-authentication
- ✅ **Real-time progress tracking**
- ✅ **Handles large backups** (500GB+)
- ✅ **Supports all file types** (configurable)
- ✅ **Resume capability** - automatically continues from where it left off if interrupted

🔒 **Privacy-First Design:**

- No credentials are stored or transmitted to any third party
- Your files download directly from Microsoft to your computer
- All data stays between your computer, Microsoft's servers, and your external drive
- Open source - review the code yourself

## Requirements

- Python 3.6+
- Internal or External hard drive with sufficient space
- Microsoft personal account with OneDrive
- Azure app registration (free, ~10 minutes one-time setup)

## Installation

1. Clone this repository:

    git clone https://github.com/davidninow/microsoft-backup-suite.git
    cd microsoft-backup-suite/onedrive-backup

2. Install required dependencies:

    pip install requests

## Setup: Azure App Registration

Before first use, you'll need to create an Azure app registration (free, one-time setup).

### Step 1: Create App Registration

1. Go to [Microsoft Entra Admin Center](https://entra.microsoft.com/)
2. Sign in with your personal Microsoft account
   - If you get errors at this point, fret not! If no errors, skip to step 3.
   - The first error you'll likely see: "Interaction Required..." - simply click `Ignore` and **quickly** click on `App Registrations` in the left sidebar (if the error reappears, just keep clicking `Ignore` and be quicker :)
3. Look for "App registrations" in the left sidebar (or search for it)
4. Click "+ New registration" button at the top **(if no errors, skip the bullets below and jump to the next step)**
   - If you haven't setup a directory previously, you'll be asked to sign up for an Azure or Dev account to create one.
   - Our most tested path is to click the link to `sign up for an Azure account`.
   - Click `Try Azure for Free`
   - Go through the setup process for personal use (name, email phone, verify), click `Next`
   - Fill out your address, click `Next`
   - This next page asks for your credit card info. ⚠️**STOP!**⚠️ you don't need to give them your CC info for this
   - Just click `Back` until you're back at the first info signup page for Azure
   - Close the Azure signup tab and go back to your App Registration page
   - Click your profile icon at the top right of the screen
   - Click `Switch Directories`
   - You should now see a `Default` or similar directory. Click the button to switch to that directory
   - Now navigate back to the App Registration page
   - Click `+ New Registration` button at the top
5. Fill out the form:
   - **Name:** `OneDrive Backup Tool`
   - **Supported account types:** "Accounts in any organizational directory and personal Microsoft accounts"
   - **Redirect URI:** Platform: `Web`, URI: `http://localhost:8080`
6. Click **Register**

### Step 2: Get Application (Client) ID

1. On the app's **Overview** page, copy the **Application (client) ID** (it's a long string like `12345678-1234-1234-1234-123456789abc`)
2. Save this somewhere (Notepad, Notes, etc.) - you'll need it when running the script

### Step 3: Create Client Secret

1. Go to **Certificates & secrets** (left sidebar)
2. Click **+ New client secret**
3. Description: `OneDrive Backup Secret`
4. Expiration: `24 months`
5. Click **Add**
6. **IMMEDIATELY copy the Value** (you can only see it once!)
   - Note: You can copy the Secret ID too if you want, but you won't need it for this process
7. Save this with your Client ID

### Step 4: Set API Permissions

1. Go to **API permissions** (left sidebar)
2. Click **+ Add a permission**
3. Select **Microsoft Graph**
4. Select **Delegated permissions**
5. Search and click the checkbox for these permissions:
   - `Files.Read.All`
   - `offline_access`
6. Click **Add permissions**
7. Click **Grant admin consent for [your account]** and confirm

You should see green checkmarks next to all permissions.

## Usage

### Quick Start

Run the script:

    python3 onedrive_backup_enhanced.py

Follow the prompts:

1. Select **"App Credentials"** login method
2. Enter your Client ID and Client Secret from the Azure setup
3. Browser opens → Sign in with your Microsoft account
4. Return to terminal
5. Enter your external drive path (e.g., `/Volumes/MyDrive` or `E:\`)
6. Choose what to backup
7. Done! ☕ Grab a coffee while it runs.

### What Gets Backed Up

By default, you can choose to backup:

**Documents:**
- PDF, Word (.docx, .doc), Excel (.xlsx, .xls)
- PowerPoint (.pptx, .ppt), Text files (.txt)
- CSV, RTF, ODT

**Pictures:**
- JPG, JPEG, PNG, GIF, BMP
- TIFF, SVG, WebP, HEIC, RAW

**Videos:**
- MP4, MOV, AVI, MKV, WMV
- And more...

**Or choose "All Files"** to backup everything!

## How It Works

    Your Computer                                      Microsoft
         │                                                  │
         │ 1. Authenticate with your Azure app credentials  │
         │─────────────────────────────────────────────────>│
         │                                                  │
         │ 2. Receive access tokens                         │
         │<─────────────────────────────────────────────────│
         │                                                  │
         │ 3. Download files directly from Microsoft        │
         │─────────────────────────────────────────────────>│

**Technical details:**

1. **Authentication:** Uses OAuth 2.0 with your Azure app registration
2. **Token Management:** Automatically refreshes access tokens
3. **API Calls:** Uses Microsoft Graph API to list and download files
4. **Structure Preservation:** Recreates exact OneDrive folder hierarchy on external drive
5. **Progress Tracking:** Shows real-time file counts, speeds, and ETAs

## Output Structure

Your backup will be organized exactly as in OneDrive:

    /Volumes/YourDrive/OneDrive_Backup_20241203_051234/
    ├── Work/
    │   ├── Projects/
    │   │   ├── Report.docx
    │   │   └── Data.xlsx
    │   └── Presentations/
    ├── Personal/
    │   ├── Photos/
    │   │   ├── 2023/
    │   │   └── 2024/
    │   └── Documents/
    └── [your exact OneDrive structure]

## Troubleshooting

### "Browser didn't open"

Copy the URL from the terminal and paste it in your browser manually.

### "Login failed"

- Make sure you're using a personal Microsoft account (work/school support coming soon)
- Verify your Client ID and Secret are correct
- Try again - sometimes Microsoft auth is slow

### "Token expired" error

The script automatically refreshes tokens. If this fails, simply run the script again.

### "Destination drive not found"

Make sure your external drive is connected and mounted. Use the exact path shown in Finder/Explorer.

### Script was interrupted

If the backup stops for any reason (power loss, crash, Ctrl+C), simply run the script again. It will automatically resume from where it left off. Progress is saved every 10 files.

### Files failed to download

After the backup completes, the script shows you exactly what failed and why. Most failures are temporary network issues - just press 'y' to retry immediately!

## Security Notes

- Access tokens expire after ~75 minutes and auto-refresh
- Refresh tokens last 90 days and auto-renew when used
- The script never stores your Microsoft password
- All authentication uses official Microsoft OAuth flows
- Files download directly from Microsoft to your computer
- Open source - review the code yourself

## Limitations

- Personal Microsoft accounts only (work/school accounts coming soon)
- Download speed depends on your internet connection
- Large files may take time to download

## Contributing

Pull requests welcome! Please ensure:

- Code follows existing style
- Add tests for new features
- Update documentation

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## License

MIT License - feel free to use and modify as needed.

## Credits

Created to solve the challenge of backing up large OneDrive accounts without local storage space.

Special thanks to everyone who tested v2.0 and reported bugs!

## Support

For issues or questions:

1. Check the Troubleshooting section above
2. Open an issue on [GitHub](https://github.com/davidninow/microsoft-backup-suite/issues)
