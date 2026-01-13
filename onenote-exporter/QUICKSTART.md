# Quick Start Guide - OneNote Exporter

## 🚀 Get Started in 5 Minutes

### Step 1: Install Dependencies (30 seconds)

```bash
pip install requests
```

Or use the requirements file:
```bash
pip install -r requirements.txt
```

### Step 2: Create Azure App (5 minutes)

This is a one-time setup:

1. **Go to:** https://entra.microsoft.com/
2. **Navigate to:** App registrations → New registration
3. **Fill in:**
   - Name: `OneNote Exporter`
   - Accounts: "Personal Microsoft accounts"
   - Redirect URI: `http://localhost:8080` (Web)
4. **Get your credentials:**
   - Copy **Application (client) ID** from Overview
   - Go to "Certificates & secrets" → New client secret
   - Copy the **Value** (not the ID!)
5. **Set permissions:**
   - API permissions → Add permission → Microsoft Graph
   - Delegated permissions: `Notes.Read`, `Notes.Read.All`, `offline_access`
   - Grant admin consent (green checkmark)

**Save these two values:**
- ✅ Application (client) ID
- ✅ Client Secret Value

### Step 3: Run the Exporter (2 minutes setup + export time)

```bash
python3 onenote_exporter.py
```

**You'll be prompted for:**

1. **Application (client) ID** → paste from Step 2
2. **Client Secret** → paste from Step 2
3. **Tenant ID** → type `common` (for personal accounts)
4. **Browser opens** → sign in with your Microsoft account
5. **Copy URL** → after signing in, copy the full URL from browser
6. **Destination** → where to save (e.g., `/Users/yourname/Desktop`)
7. **Format** → choose export format (1 = both Joplin and Evernote)

### Step 4: Import Your Notes

#### For Joplin:
```
File → Import → MD - Markdown (Directory)
Select: [exported_folder]/[notebook_name]/joplin/
```

#### For Evernote:
```
File → Import Notes → Evernote Export File
Select: [exported_folder]/[notebook_name]/evernote/*.enex
```

## 📊 What to Expect

### Export Times (Approximate)
- Small notebook (10-50 pages): 1-2 minutes
- Medium notebook (100-200 pages): 5-10 minutes
- Large notebook (500+ pages): 20-30 minutes
- Multiple notebooks: Varies based on total size

### Exported Files
```
OneNote_Export_20241203_143052/
├── README.md              ← Import instructions
├── export_summary.json    ← Statistics
└── [Your Notebooks]/
    ├── [Sections]/
    │   ├── *.html         ← Raw HTML files
    │   └── *_attachments/ ← All media files
    ├── joplin/            ← Markdown files
    └── evernote/          ← ENEX files
```

## 🎯 Common Use Cases

### Scenario 1: Moving to Joplin
```bash
python3 onenote_exporter.py
# Choose format: 2 (Joplin only)
# Import markdown files to Joplin
```

### Scenario 2: Backup Everything
```bash
python3 onenote_exporter.py
# Choose format: 1 (Both formats)
# Keep HTML files as backup
```

### Scenario 3: Migration to Evernote
```bash
python3 onenote_exporter.py
# Choose format: 3 (Evernote only)
# Import ENEX files one at a time
```

## ⚠️ Important Notes

### Before You Start
- ✅ Ensure stable internet connection
- ✅ Have enough disk space (estimate 2x your OneNote size)
- ✅ Close OneNote application (not required but recommended)
- ✅ Test with a small notebook first

### During Export
- 🔄 Don't close the terminal window
- 🔄 The script shows real-time progress
- 🔄 Token refreshes automatically
- 🔄 Ctrl+C to pause (resume capability coming soon)

### After Export
- ✅ Check export_summary.json for statistics
- ✅ Review README.md in export folder
- ✅ Test import with one notebook first
- ✅ Keep original OneNote until verified

## 🐛 Quick Troubleshooting

### "Invalid client secret"
→ Copy the **Value** not the **Secret ID** from Azure

### "No notebooks found"
→ Check Azure permissions are granted (green checkmarks)

### Browser doesn't open
→ Manually open the URL shown in terminal

### Downloads failing
→ Check internet connection, some large files may timeout

### Import fails in Joplin
→ Make sure you select "Markdown (Directory)" not "Markdown (File)"

## 💡 Pro Tips

1. **Large Notebooks:** Export during off-peak hours for better speed
2. **Attachments:** Audio/video files take longest to download
3. **Format Choice:** Use "Both" if unsure which app you'll use
4. **Testing:** Export one small notebook first to verify setup
5. **Storage:** External drive recommended for very large exports

## 📈 What's Exported

✅ All text and formatting  
✅ Images and screenshots  
✅ Audio recordings  
✅ PDF attachments  
✅ Links and tables  
✅ Creation/modification dates  

❌ OneNote tags (to-do checkboxes)  
❌ Handwriting as searchable text (exported as images)  
❌ Some advanced formatting  

## 🆘 Need Help?

1. Read the full README_ONENOTE.md
2. Check the Troubleshooting section
3. Review export_summary.json for errors
4. Open an issue on GitHub with error details

## 🎉 Success Checklist

- [ ] Azure app created with correct permissions
- [ ] Script ran without errors
- [ ] Export folder contains all notebooks
- [ ] Attachments downloaded successfully
- [ ] Test import successful in target app
- [ ] Original notes verified as intact

---

**You're ready to export! Any questions? Check the full documentation in README_ONENOTE.md**
