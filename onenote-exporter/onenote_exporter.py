#!/usr/bin/env python3
"""
OneNote Export Tool
Exports OneNote notebooks with all attachments for import into Evernote, Joplin, etc.
"""

import os
import json
import requests
import webbrowser
import getpass
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import base64
import html
import re
from typing import Dict, List, Optional, Tuple
import mimetypes

class OneNoteExporter:
    def __init__(self):
        self.access_token = None
        self.refresh_token = None
        self.client_id = None
        self.client_secret = None
        self.tenant_id = None
        self.export_root = None
        self.stats = {
            'notebooks': 0,
            'sections': 0,
            'pages': 0,
            'attachments': 0,
            'audio_files': 0,
            'images': 0,
            'pdfs': 0,
            'errors': 0
        }
        
    def authenticate(self):
        """Authenticate with Microsoft Graph API"""
        print("\n" + "="*70)
        print("OneNote Export Tool - Authentication")
        print("="*70)
        print("\n📋 You need a Microsoft App Registration to use this tool.")
        print("\nQuick Setup Instructions:")
        print("1. Go to: https://entra.microsoft.com/")
        print("2. Navigate to App registrations → New registration")
        print("3. Name: 'OneNote Exporter'")
        print("4. Supported accounts: 'Personal Microsoft accounts only'")
        print("5. Redirect URI: Web → http://localhost:8080")
        print("6. After registration:")
        print("   - Copy Application (client) ID")
        print("   - Create Client Secret (Certificates & secrets)")
        print("   - Add API permissions: Notes.Read, Notes.Read.All (Delegated)")
        print("   - Grant admin consent")
        print("="*70 + "\n")
        
        self.client_id = input("Enter Application (client) ID: ").strip()
        self.client_secret = getpass.getpass("Enter Client Secret (hidden): ")
        self.tenant_id = input("Enter Tenant ID (or 'common' for personal): ").strip() or "common"
        
        return self.delegated_auth_flow()
    
    def delegated_auth_flow(self):
        """Interactive auth flow for personal accounts"""
        print("\n🔐 Starting authentication...")
        print("A browser window will open for you to sign in.\n")
        
        redirect_uri = "http://localhost:8080"
        scope = "Notes.Read Notes.Read.All offline_access"
        auth_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/authorize"
        auth_url += f"?client_id={self.client_id}"
        auth_url += f"&response_type=code"
        auth_url += f"&redirect_uri={redirect_uri}"
        auth_url += f"&scope={scope}"
        
        print("Opening browser for authentication...")
        webbrowser.open(auth_url)
        
        print("\nAfter signing in, copy the full URL from your browser.")
        print("(It will show an error page, but that's normal)")
        redirect_response = input("\nPaste the redirect URL here: ").strip()
        
        try:
            parsed = urlparse(redirect_response)
            code = parse_qs(parsed.query)['code'][0]
        except:
            print("❌ Could not extract authorization code from URL")
            return False
        
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
                print("✅ Successfully authenticated!\n")
                return True
            else:
                print(f"❌ Authentication failed: {result.get('error_description', 'Unknown error')}")
                return False
        except Exception as e:
            print(f"❌ Authentication error: {e}")
            return False
    
    def refresh_access_token(self):
        """Refresh the access token"""
        if not self.refresh_token:
            return False
        
        print("🔄 Refreshing access token...")
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
                print("✅ Token refreshed!")
                return True
            else:
                return False
        except:
            return False
    
    def make_api_request(self, url, method='GET', data=None):
        """Make API request with automatic token refresh"""
        headers = {'Authorization': f'Bearer {self.access_token}'}
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=60)
            else:
                response = requests.post(url, headers=headers, json=data, timeout=60)
            
            if response.status_code == 401 and self.refresh_token:
                if self.refresh_access_token():
                    headers['Authorization'] = f'Bearer {self.access_token}'
                    if method == 'GET':
                        response = requests.get(url, headers=headers, timeout=60)
                    else:
                        response = requests.post(url, headers=headers, json=data, timeout=60)
            
            return response
        except Exception as e:
            print(f"❌ API request error: {e}")
            return None
    
    def get_notebooks(self):
        """Get all OneNote notebooks"""
        url = "https://graph.microsoft.com/v1.0/me/onenote/notebooks"
        response = self.make_api_request(url)
        
        if response and response.status_code == 200:
            return response.json().get('value', [])
        return []
    
    def get_sections(self, notebook_id):
        """Get all sections in a notebook"""
        url = f"https://graph.microsoft.com/v1.0/me/onenote/notebooks/{notebook_id}/sections"
        response = self.make_api_request(url)
        
        if response and response.status_code == 200:
            return response.json().get('value', [])
        return []
    
    def get_pages(self, section_id):
        """Get all pages in a section"""
        url = f"https://graph.microsoft.com/v1.0/me/onenote/sections/{section_id}/pages"
        response = self.make_api_request(url)
        
        if response and response.status_code == 200:
            return response.json().get('value', [])
        return []
    
    def get_page_content(self, page_id):
        """Get page content in HTML format"""
        url = f"https://graph.microsoft.com/v1.0/me/onenote/pages/{page_id}/content"
        response = self.make_api_request(url)
        
        if response and response.status_code == 200:
            return response.text
        return None
    
    def sanitize_filename(self, filename):
        """Sanitize filename for filesystem"""
        # Remove or replace invalid characters
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        filename = filename.strip('. ')
        if not filename:
            filename = 'untitled'
        return filename[:200]  # Limit length
    
    def extract_attachments(self, html_content, page_path):
        """Extract and download all attachments from page HTML"""
        attachments = []
        attachments_dir = page_path.parent / f"{page_path.stem}_attachments"
        attachments_dir.mkdir(exist_ok=True)
        
        # Find all data-attachment tags (embedded files)
        attachment_pattern = r'data-attachment="([^"]+)"[^>]*src="([^"]+)"'
        for match in re.finditer(attachment_pattern, html_content):
            filename = match.group(1)
            url = match.group(2)
            
            if url.startswith('data:'):
                # Base64 embedded data
                self.save_base64_attachment(url, filename, attachments_dir)
                attachments.append(filename)
            else:
                # URL to download
                self.download_attachment(url, filename, attachments_dir)
                attachments.append(filename)
        
        # Find all img tags
        img_pattern = r'<img[^>]*src="([^"]+)"[^>]*(?:data-fullres-src="([^"]+)")?'
        img_count = 0
        for match in re.finditer(img_pattern, html_content):
            img_count += 1
            src = match.group(1)
            fullres = match.group(2) if match.group(2) else src
            
            # Use fullres if available
            url = fullres if fullres else src
            
            if url.startswith('data:'):
                filename = f"image_{img_count}.png"
                self.save_base64_attachment(url, filename, attachments_dir)
                attachments.append(filename)
                self.stats['images'] += 1
            elif url.startswith('http'):
                # Extract extension from URL or use png
                ext = self.get_extension_from_url(url) or 'png'
                filename = f"image_{img_count}.{ext}"
                if self.download_attachment(url, filename, attachments_dir):
                    attachments.append(filename)
                    self.stats['images'] += 1
        
        # Find all object/embed tags (PDFs, audio, video)
        object_pattern = r'<object[^>]*data="([^"]+)"[^>]*type="([^"]+)"'
        for match in re.finditer(object_pattern, html_content):
            url = match.group(1)
            mime_type = match.group(2)
            
            ext = mimetypes.guess_extension(mime_type) or '.bin'
            filename = f"attachment_{len(attachments) + 1}{ext}"
            
            if self.download_attachment(url, filename, attachments_dir):
                attachments.append(filename)
                self.stats['attachments'] += 1
                
                if 'audio' in mime_type:
                    self.stats['audio_files'] += 1
                elif 'pdf' in mime_type:
                    self.stats['pdfs'] += 1
        
        # Find audio tags
        audio_pattern = r'<audio[^>]*src="([^"]+)"'
        audio_count = 0
        for match in re.finditer(audio_pattern, html_content):
            audio_count += 1
            url = match.group(1)
            ext = self.get_extension_from_url(url) or 'm4a'
            filename = f"audio_{audio_count}.{ext}"
            
            if self.download_attachment(url, filename, attachments_dir):
                attachments.append(filename)
                self.stats['audio_files'] += 1
        
        return attachments, attachments_dir
    
    def save_base64_attachment(self, data_url, filename, attachments_dir):
        """Save base64 encoded attachment"""
        try:
            # Parse data URL: data:mime/type;base64,xxxxx
            match = re.match(r'data:([^;]+);base64,(.+)', data_url)
            if match:
                mime_type = match.group(1)
                base64_data = match.group(2)
                
                # Decode base64
                file_data = base64.b64decode(base64_data)
                
                # Determine extension
                ext = mimetypes.guess_extension(mime_type)
                if ext and not filename.endswith(ext):
                    filename = f"{filename}{ext}"
                
                filepath = attachments_dir / self.sanitize_filename(filename)
                with open(filepath, 'wb') as f:
                    f.write(file_data)
                
                return True
        except Exception as e:
            print(f"  ⚠️  Failed to save base64 attachment {filename}: {e}")
            self.stats['errors'] += 1
        return False
    
    def download_attachment(self, url, filename, attachments_dir):
        """Download attachment from URL"""
        try:
            headers = {'Authorization': f'Bearer {self.access_token}'}
            response = requests.get(url, headers=headers, timeout=120)
            
            if response.status_code == 200:
                filepath = attachments_dir / self.sanitize_filename(filename)
                with open(filepath, 'wb') as f:
                    f.write(response.content)
                return True
        except Exception as e:
            print(f"  ⚠️  Failed to download {filename}: {e}")
            self.stats['errors'] += 1
        return False
    
    def get_extension_from_url(self, url):
        """Extract file extension from URL"""
        path = urlparse(url).path
        ext = Path(path).suffix
        return ext.lstrip('.') if ext else None
    
    def convert_html_to_markdown(self, html_content):
        """Convert HTML to Markdown (simple conversion)"""
        # This is a basic conversion - for production use, consider using html2text library
        md = html_content
        
        # Remove OneNote-specific tags
        md = re.sub(r'<\?xml[^>]*>', '', md)
        md = re.sub(r'data-id="[^"]*"', '', md)
        
        # Convert headers
        md = re.sub(r'<h1[^>]*>(.*?)</h1>', r'# \1\n', md, flags=re.DOTALL)
        md = re.sub(r'<h2[^>]*>(.*?)</h2>', r'## \1\n', md, flags=re.DOTALL)
        md = re.sub(r'<h3[^>]*>(.*?)</h3>', r'### \1\n', md, flags=re.DOTALL)
        
        # Convert lists
        md = re.sub(r'<ul[^>]*>', '\n', md)
        md = re.sub(r'</ul>', '\n', md)
        md = re.sub(r'<li[^>]*>(.*?)</li>', r'- \1\n', md, flags=re.DOTALL)
        
        # Convert formatting
        md = re.sub(r'<strong[^>]*>(.*?)</strong>', r'**\1**', md, flags=re.DOTALL)
        md = re.sub(r'<em[^>]*>(.*?)</em>', r'*\1*', md, flags=re.DOTALL)
        md = re.sub(r'<b[^>]*>(.*?)</b>', r'**\1**', md, flags=re.DOTALL)
        md = re.sub(r'<i[^>]*>(.*?)</i>', r'*\1*', md, flags=re.DOTALL)
        
        # Convert links
        md = re.sub(r'<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>', r'[\2](\1)', md, flags=re.DOTALL)
        
        # Convert images
        md = re.sub(r'<img[^>]*src="([^"]+)"[^>]*alt="([^"]*)"[^>]*>', r'![\2](\1)', md)
        md = re.sub(r'<img[^>]*src="([^"]+)"[^>]*>', r'![](\1)', md)
        
        # Remove remaining HTML tags
        md = re.sub(r'<[^>]+>', '', md)
        
        # Clean up whitespace
        md = re.sub(r'\n\s*\n\s*\n', '\n\n', md)
        
        # Decode HTML entities
        md = html.unescape(md)
        
        return md.strip()
    
    def export_for_joplin(self, notebook_folder, page_title, page_content, attachments_dir, metadata):
        """Export page in Joplin format (Markdown with frontmatter)"""
        md_content = self.convert_html_to_markdown(page_content)
        
        # Update image/attachment references
        if attachments_dir.exists():
            attachment_folder_name = attachments_dir.name
            md_content = re.sub(
                r'!\[([^\]]*)\]\((?:data:[^)]+|https?://[^)]+)\)',
                rf'![\1]({attachment_folder_name}/image_\1.png)',
                md_content
            )
        
        # Create Joplin markdown file
        joplin_file = notebook_folder / 'joplin' / f"{self.sanitize_filename(page_title)}.md"
        joplin_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(joplin_file, 'w', encoding='utf-8') as f:
            f.write(f"# {page_title}\n\n")
            f.write(f"Created: {metadata['created']}\n")
            f.write(f"Modified: {metadata['modified']}\n\n")
            f.write(md_content)
        
        return joplin_file
    
    def export_for_evernote(self, notebook_folder, page_title, page_content, attachments, metadata):
        """Export page in ENEX format (Evernote XML)"""
        # Create ENEX file
        enex_file = notebook_folder / 'evernote' / f"{self.sanitize_filename(page_title)}.enex"
        enex_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Clean HTML for Evernote
        content = page_content
        content = re.sub(r'data-id="[^"]*"', '', content)
        content = html.escape(content)
        
        enex_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE en-export SYSTEM "http://xml.evernote.com/pub/evernote-export3.dtd">
<en-export export-date="{datetime.now().strftime('%Y%m%dT%H%M%SZ')}" application="OneNote Exporter" version="1.0">
  <note>
    <title>{html.escape(page_title)}</title>
    <content><![CDATA[<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE en-note SYSTEM "http://xml.evernote.com/pub/enml2.dtd">
<en-note>
{content}
</en-note>]]></content>
    <created>{metadata['created']}</created>
    <updated>{metadata['modified']}</updated>
  </note>
</en-export>
"""
        
        with open(enex_file, 'w', encoding='utf-8') as f:
            f.write(enex_content)
        
        return enex_file
    
    def export_notebook(self, notebook, export_formats=['both']):
        """Export a single notebook"""
        notebook_name = self.sanitize_filename(notebook['displayName'])
        notebook_folder = self.export_root / notebook_name
        notebook_folder.mkdir(exist_ok=True)
        
        print(f"\n📓 Exporting notebook: {notebook['displayName']}")
        print(f"   Location: {notebook_folder}")
        
        sections = self.get_sections(notebook['id'])
        self.stats['notebooks'] += 1
        
        for section in sections:
            section_name = self.sanitize_filename(section['displayName'])
            section_folder = notebook_folder / section_name
            section_folder.mkdir(exist_ok=True)
            
            print(f"\n  📑 Section: {section['displayName']}")
            self.stats['sections'] += 1
            
            pages = self.get_pages(section['id'])
            
            for idx, page in enumerate(pages, 1):
                try:
                    page_title = page['title'] or f"Untitled_{idx}"
                    print(f"    [{idx}/{len(pages)}] 📄 {page_title[:50]}", end='')
                    
                    # Get page content
                    page_content = self.get_page_content(page['id'])
                    if not page_content:
                        print(" ⚠️  No content")
                        continue
                    
                    # Save raw HTML
                    html_file = section_folder / f"{self.sanitize_filename(page_title)}.html"
                    with open(html_file, 'w', encoding='utf-8') as f:
                        f.write(page_content)
                    
                    # Extract attachments
                    attachments, attachments_dir = self.extract_attachments(page_content, html_file)
                    
                    # Metadata
                    metadata = {
                        'created': page.get('createdDateTime', ''),
                        'modified': page.get('lastModifiedDateTime', ''),
                        'author': page.get('createdBy', {}).get('user', {}).get('displayName', 'Unknown')
                    }
                    
                    # Export in requested formats
                    if 'joplin' in export_formats or 'both' in export_formats:
                        self.export_for_joplin(notebook_folder, page_title, page_content, attachments_dir, metadata)
                    
                    if 'evernote' in export_formats or 'both' in export_formats:
                        self.export_for_evernote(notebook_folder, page_title, page_content, attachments, metadata)
                    
                    self.stats['pages'] += 1
                    
                    # Show attachment count
                    if attachments:
                        print(f" ✓ ({len(attachments)} attachments)")
                    else:
                        print(" ✓")
                    
                except Exception as e:
                    print(f" ❌ Error: {e}")
                    self.stats['errors'] += 1
    
    def export_all(self, destination_path, export_formats=['both']):
        """Export all notebooks"""
        self.export_root = Path(destination_path)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.export_root = self.export_root / f"OneNote_Export_{timestamp}"
        self.export_root.mkdir(parents=True, exist_ok=True)
        
        print(f"\n💾 Export destination: {self.export_root}\n")
        print("="*70)
        print("Starting OneNote Export")
        print("="*70)
        
        notebooks = self.get_notebooks()
        
        if not notebooks:
            print("❌ No notebooks found!")
            return False
        
        print(f"\nFound {len(notebooks)} notebook(s)")
        
        for notebook in notebooks:
            try:
                self.export_notebook(notebook, export_formats)
            except Exception as e:
                print(f"\n❌ Error exporting notebook {notebook['displayName']}: {e}")
                self.stats['errors'] += 1
        
        # Save export summary
        summary_file = self.export_root / "export_summary.json"
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump({
                'timestamp': timestamp,
                'statistics': self.stats,
                'export_path': str(self.export_root)
            }, f, indent=2)
        
        # Create README
        self.create_import_instructions()
        
        # Print summary
        self.print_summary()
        
        return True
    
    def create_import_instructions(self):
        """Create instructions for importing to other apps"""
        readme_content = f"""# OneNote Export Summary

Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Statistics

- Notebooks: {self.stats['notebooks']}
- Sections: {self.stats['sections']}
- Pages: {self.stats['pages']}
- Total Attachments: {self.stats['attachments']}
  - Images: {self.stats['images']}
  - Audio Files: {self.stats['audio_files']}
  - PDFs: {self.stats['pdfs']}
- Errors: {self.stats['errors']}

## Folder Structure

```
OneNote_Export_YYYYMMDD_HHMMSS/
├── Notebook1/
│   ├── Section1/
│   │   ├── page1.html (raw HTML)
│   │   ├── page1_attachments/ (images, audio, PDFs)
│   │   └── ...
│   ├── joplin/ (Markdown files for Joplin)
│   └── evernote/ (ENEX files for Evernote)
└── ...
```

## Importing to Joplin

1. Open Joplin
2. Go to File → Import → Markdown
3. Select the 'joplin' folder from any notebook
4. Joplin will import all markdown files
5. Copy the corresponding '_attachments' folders to Joplin's resource folder
   - Location: ~/.config/joplin-desktop/resources/ (Linux/Mac)
   - Location: %USERPROFILE%/.config/joplin-desktop/resources/ (Windows)

## Importing to Evernote

1. Open Evernote desktop application
2. Go to File → Import → Evernote Export Files (.enex)
3. Select ENEX files from the 'evernote' folder
4. Files will be imported into Evernote

Note: Evernote has limitations on attachment types and sizes.

## Importing to Notion

1. For each page, use the HTML files directly
2. In Notion: Import → HTML
3. Select individual HTML files
4. Manually add attachments from '_attachments' folders

## Raw HTML Files

All pages are also saved as raw HTML files in each section folder.
These can be opened in any web browser or imported to other tools.

## Attachments

All attachments are saved in folders named `[page_name]_attachments/`
These include:
- Images (PNG, JPG, etc.)
- Audio recordings (M4A, WAV, etc.)
- PDF documents
- Other embedded files

## Troubleshooting

### Missing Attachments
- Some attachments may have failed to download due to:
  - Network timeouts
  - Microsoft API limitations
  - File size restrictions

### Format Issues
- Some formatting may not transfer perfectly between apps
- Review imported notes and adjust as needed

### Large Exports
- Very large notebooks may take a long time to export
- Consider exporting notebooks individually if experiencing timeouts

## Next Steps

1. Review the exported content
2. Import to your preferred note-taking app
3. Verify that attachments are properly linked
4. Delete the export folder once import is complete

For issues or questions, please check the project documentation.
"""
        
        readme_file = self.export_root / "README.md"
        with open(readme_file, 'w', encoding='utf-8') as f:
            f.write(readme_content)
    
    def print_summary(self):
        """Print export summary"""
        print("\n" + "="*70)
        print("📊 EXPORT SUMMARY")
        print("="*70)
        print(f"Notebooks exported:     {self.stats['notebooks']}")
        print(f"Sections processed:     {self.stats['sections']}")
        print(f"Pages exported:         {self.stats['pages']}")
        print(f"Total attachments:      {self.stats['attachments']}")
        print(f"  - Images:             {self.stats['images']}")
        print(f"  - Audio files:        {self.stats['audio_files']}")
        print(f"  - PDFs:               {self.stats['pdfs']}")
        if self.stats['errors'] > 0:
            print(f"Errors encountered:     {self.stats['errors']}")
        print(f"\nExport location:        {self.export_root}")
        print(f"Import instructions:    {self.export_root / 'README.md'}")
        print("="*70)


def main():
    print("="*70)
    print("OneNote Export Tool")
    print("Export OneNote notebooks with attachments for Evernote, Joplin, etc.")
    print("="*70)
    
    exporter = OneNoteExporter()
    
    # Authenticate
    if not exporter.authenticate():
        print("\n❌ Authentication failed. Exiting.")
        return
    
    # Get destination
    print("\n📁 Where would you like to save the export?")
    destination = input("Enter path (e.g., /Users/yourname/Desktop): ").strip()
    
    if not destination:
        destination = str(Path.home() / "Desktop")
        print(f"Using default: {destination}")
    
    # Choose export format
    print("\n📝 Export format:")
    print("1. Both Joplin (Markdown) and Evernote (ENEX)")
    print("2. Joplin only")
    print("3. Evernote only")
    print("4. Raw HTML only")
    
    choice = input("Enter choice (1-4): ").strip()
    
    format_map = {
        '1': ['both'],
        '2': ['joplin'],
        '3': ['evernote'],
        '4': []
    }
    
    export_formats = format_map.get(choice, ['both'])
    
    # Start export
    print("\n🚀 Starting export...")
    print("This may take a while for large notebooks...\n")
    
    success = exporter.export_all(destination, export_formats)
    
    if success:
        print("\n✅ Export complete!")
        print(f"\n📂 Your exported notebooks are ready at:")
        print(f"   {exporter.export_root}")
        print(f"\n📖 Read the README.md file for import instructions")
    else:
        print("\n⚠️  Export completed with errors. Check the output above.")


if __name__ == "__main__":
    main()
