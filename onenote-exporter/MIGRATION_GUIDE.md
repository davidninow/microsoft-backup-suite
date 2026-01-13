# OneNote to Other Apps - Migration Guide

This guide helps you choose the best note-taking app for your needs and provides specific import instructions.

## 🎯 Quick Comparison

| Feature | Joplin | Evernote | Notion | Obsidian | Apple Notes |
|---------|--------|----------|--------|----------|-------------|
| **Price** | Free | Free/Premium | Free/Paid | Free | Free |
| **Offline** | ✅ Yes | ⚠️ Limited | ❌ No | ✅ Yes | ✅ Yes |
| **Open Source** | ✅ Yes | ❌ No | ❌ No | ⚠️ Partial | ❌ No |
| **Attachments** | ✅ Full | ⚠️ Limited | ✅ Full | ✅ Full | ✅ Full |
| **Audio Notes** | ✅ Yes | ✅ Yes | ⚠️ Via embed | ✅ Yes | ✅ Yes |
| **Platform** | All | All | Web/Apps | All | Apple only |
| **Markdown** | ✅ Native | ❌ No | ⚠️ Partial | ✅ Native | ❌ No |
| **Import Format** | MD/HTML | ENEX | HTML | MD | HTML/PDF |

## 📱 Detailed App Comparison

### Joplin - Best for Privacy & Open Source

**✅ Pros:**
- Completely free and open source
- End-to-end encryption support
- Works offline
- Markdown native
- Cross-platform (Windows, Mac, Linux, iOS, Android)
- Self-hosting options
- No size limits
- Active community

**❌ Cons:**
- Less polished UI than commercial apps
- Syncing requires setup
- Learning curve for Markdown
- Some features require plugins

**Best For:**
- Privacy-conscious users
- Developers and tech-savvy users
- Those who want full control of their data
- Users who like Markdown

**Import Process:**
1. Export using format option `2` (Joplin only) or `1` (Both)
2. In Joplin: `File → Import → MD - Markdown (Directory)`
3. Select the `joplin` folder from exported notebook
4. For attachments: Copy `*_attachments` folders to `~/.config/joplin-desktop/resources/`

**What Transfers Well:**
- ✅ Text and basic formatting
- ✅ Images (as embedded files)
- ✅ Audio recordings
- ✅ PDFs and attachments
- ✅ Links and tables
- ⚠️ Some formatting may be simplified

---

### Evernote - Best for OneNote-Like Experience

**✅ Pros:**
- Similar to OneNote in features
- Excellent OCR and search
- Good mobile apps
- Web clipper
- Strong organization features
- Reliable sync

**❌ Cons:**
- Free tier very limited (60MB/month upload)
- Premium expensive ($10-15/month)
- Vendor lock-in
- Less control over data
- Occasional sync issues

**Best For:**
- Former OneNote power users
- Those who need strong search/OCR
- Users who want ease of use
- Those willing to pay for premium

**Import Process:**
1. Export using format option `3` (Evernote only) or `1` (Both)
2. In Evernote: `File → Import Notes → Evernote Export File`
3. Select ENEX files one at a time
4. Choose target notebook
5. Wait for import to complete

**What Transfers Well:**
- ✅ Text and rich formatting
- ✅ Images inline
- ⚠️ Audio (but with size limits)
- ⚠️ PDFs (with premium account)
- ⚠️ Large attachments (may hit limits)
- ❌ Some complex tables

**Size Limits:**
- Free: 60MB/month, 25MB per note
- Premium: 10GB/month, 200MB per note

---

### Notion - Best for Teams & Databases

**✅ Pros:**
- Beautiful, modern interface
- Powerful databases and relations
- Great collaboration features
- Templates and views
- Embeds from many services
- Free for personal use

**❌ Cons:**
- Requires internet connection
- No true offline mode
- Can be slow with large content
- Import process manual
- Not ideal for quick notes

**Best For:**
- Team collaboration
- Project management
- Wiki-style knowledge bases
- Those who like visual organization

**Import Process:**
1. Export using format option `4` (HTML only) or `1` (Both)
2. In Notion: Create a new page → `Import → HTML`
3. Select HTML files from exported notebooks
4. Manually drag attachments into imported pages
5. Reorganize into Notion's structure

**What Transfers Well:**
- ✅ Text content
- ⚠️ Formatting (may need adjustment)
- ⚠️ Images (manual embedding)
- ⚠️ Attachments (manual upload)
- ❌ Audio (needs re-embedding)
- ❌ Complex layouts

**Note:** Notion import is more manual than other options. Best for smaller migrations or when you want to restructure content.

---

### Obsidian - Best for Linking & Knowledge Management

**✅ Pros:**
- Fast and lightweight
- Local-first (files on your computer)
- Powerful linking and graph view
- Markdown native
- Extensive plugin ecosystem
- Free for personal use
- Works offline

**❌ Cons:**
- Sync costs extra ($10/month)
- Learning curve for advanced features
- Mobile apps require setup
- No built-in OCR

**Best For:**
- Researchers and writers
- Building a "second brain"
- Those who value speed and simplicity
- Users comfortable with file systems

**Import Process:**
1. Export using custom Obsidian format (see advanced_examples.py)
2. Or use format option `2` (Joplin/Markdown)
3. Copy exported markdown files to your Obsidian vault folder
4. Copy `*_attachments` folders into vault
5. Open Obsidian and files appear automatically

**What Transfers Well:**
- ✅ Text content
- ✅ Markdown formatting
- ✅ Images (as linked files)
- ✅ PDFs and attachments
- ⚠️ Some rich formatting lost
- ⚠️ Audio (as file links)

---

### Apple Notes - Best for Apple Ecosystem

**✅ Pros:**
- Seamless Apple ecosystem sync
- Simple and intuitive
- Good handwriting support (iPad)
- Face ID/Touch ID protection
- Free with Apple devices
- Excellent search

**❌ Cons:**
- Apple devices only
- Limited formatting options
- No markdown support
- Limited organization
- No web access
- Can't export easily

**Best For:**
- Existing Apple users
- Those who want simplicity
- iPad/Apple Pencil users
- Casual note-taking

**Import Process:**
1. Export using format option `4` (HTML)
2. Open HTML files in Safari
3. Copy content from browser
4. Paste into new Apple Notes
5. Manually drag attachments into notes

**What Transfers Well:**
- ✅ Basic text
- ✅ Images inline
- ⚠️ Some formatting
- ⚠️ Attachments (manual)
- ❌ Audio (re-upload needed)
- ❌ Complex tables

---

## 🎯 Decision Tree

**I value privacy and want full control →** Joplin or Obsidian

**I want something like OneNote →** Evernote

**I need team collaboration →** Notion

**I'm in the Apple ecosystem →** Apple Notes

**I want to build a knowledge graph →** Obsidian

**I want free with good features →** Joplin

**I need the best mobile app →** Evernote or Notion

**I want to future-proof my notes →** Joplin or Obsidian (plain text files)

## 📊 Feature Comparison Details

### Attachment Support

**Joplin:**
- Unlimited attachments
- Stored as separate files
- Can be in any format
- Synced with notes

**Evernote:**
- Free: 25MB per note
- Premium: 200MB per note
- Some file types restricted on free tier

**Notion:**
- 5MB file upload on free (10MB with blocks)
- No limit on premium
- Can embed from cloud storage

**Obsidian:**
- Unlimited (files stored locally)
- Any file type
- Full control over organization

### Markdown Support

**Native Markdown:**
- Joplin ✅
- Obsidian ✅

**Markdown Import:**
- Notion ⚠️ (converts to blocks)
- Evernote ❌

**Markdown Export:**
- Joplin ✅
- Obsidian ✅
- Notion ⚠️ (limited)
- Evernote ❌

### Offline Access

**Full Offline:**
- Joplin ✅
- Obsidian ✅
- Apple Notes ✅

**Limited Offline:**
- Evernote ⚠️ (premium only)
- Notion ❌ (view only)

### Sync Options

**Joplin:**
- Dropbox, OneDrive, WebDAV
- Self-hosted (Joplin Cloud)
- File system sync

**Evernote:**
- Built-in cloud sync
- Automatic across devices

**Notion:**
- Built-in cloud sync
- Real-time collaboration

**Obsidian:**
- Obsidian Sync ($10/month)
- iCloud, Dropbox, etc.
- Git for version control

## 💡 Migration Tips by App

### Joplin Tips

1. **Install plugins first:**
   - Rich Markdown
   - Note Tabs
   - Inline Tags
   - Attachment Name Formatter

2. **Set up sync early:**
   - Choose sync target
   - Configure before importing
   - Test with small notebook first

3. **Organize attachments:**
   - Keep attachment folders organized
   - Use relative paths in markdown
   - Consider external storage for large files

4. **Customize appearance:**
   - Try different themes
   - Adjust editor settings
   - Enable side-by-side view

### Evernote Tips

1. **Check size limits:**
   - Review attachment sizes before import
   - Split large notebooks if needed
   - Consider premium for large imports

2. **Import gradually:**
   - One notebook at a time
   - Verify each import
   - Check for missing attachments

3. **Organize tags:**
   - Use tags for categories
   - Create notebooks structure
   - Set up shortcuts

4. **Use web clipper:**
   - Install browser extension
   - Better than copy-paste
   - Preserves formatting

### Notion Tips

1. **Plan structure first:**
   - Design your workspace
   - Create template pages
   - Set up databases

2. **Import selectively:**
   - Don't import everything
   - Choose important notes
   - Restructure as you go

3. **Use templates:**
   - Create note templates
   - Consistent formatting
   - Faster entry

4. **Leverage databases:**
   - Convert notes to database items
   - Add properties
   - Create views

### Obsidian Tips

1. **Set up vault:**
   - Choose location wisely
   - Consider sync setup
   - Enable core plugins

2. **Use wikilinks:**
   - Link notes together
   - Build knowledge graph
   - Use aliases

3. **Customize plugins:**
   - Templater for templates
   - Dataview for queries
   - Calendar for daily notes

4. **Master search:**
   - Learn search syntax
   - Use tags effectively
   - Create MOCs (Maps of Content)

## 🔄 Multi-App Strategy

You don't have to choose just one! Consider:

**Joplin for personal notes** + **Notion for team projects**
**Obsidian for knowledge base** + **Apple Notes for quick capture**
**Evernote for web clips** + **Joplin for private notes**

## 📝 Post-Migration Checklist

- [ ] All notebooks imported
- [ ] Attachments accessible
- [ ] Audio files playable
- [ ] Images display correctly
- [ ] Links work properly
- [ ] Formatting acceptable
- [ ] Search functions work
- [ ] Sync configured (if applicable)
- [ ] Backup created
- [ ] Original OneNote preserved (until verified)

## 🆘 Common Issues & Solutions

### Import Failed

**Joplin:**
- Check file encoding (UTF-8)
- Try smaller batches
- Verify markdown syntax

**Evernote:**
- Check file size limits
- Validate ENEX format
- Try one file at a time

**Notion:**
- Check HTML validity
- Try different browsers
- Manual copy-paste as fallback

### Missing Attachments

**Solution:**
1. Check `*_attachments` folders
2. Verify files downloaded
3. Manually add if needed
4. Update links in notes

### Formatting Lost

**Solution:**
1. Accept some loss (normal)
2. Focus on content, not format
3. Re-format critical notes
4. Use plain text when possible

### Large Files Won't Import

**Solution:**
1. Check app size limits
2. Host large files externally
3. Link instead of embedding
4. Compress if possible

---

**Need help deciding? Consider:**
- Try multiple apps with a test notebook
- Check what your team/collaborators use
- Consider long-term data portability
- Think about your typical workflow

**Remember:** The best app is the one you'll actually use consistently!
