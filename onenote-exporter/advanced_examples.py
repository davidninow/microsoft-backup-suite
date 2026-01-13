#!/usr/bin/env python3
"""
Advanced OneNote Export Examples
Demonstrates custom export scenarios and advanced features
"""

from onenote_exporter import OneNoteExporter
from pathlib import Path
import json

# Example 1: Export specific notebooks only
def export_specific_notebooks(exporter, notebook_names, destination):
    """Export only specified notebooks by name"""
    print(f"\n📚 Exporting specific notebooks: {', '.join(notebook_names)}")
    
    all_notebooks = exporter.get_notebooks()
    selected_notebooks = [nb for nb in all_notebooks if nb['displayName'] in notebook_names]
    
    if not selected_notebooks:
        print("❌ No matching notebooks found!")
        return
    
    exporter.export_root = Path(destination)
    
    for notebook in selected_notebooks:
        exporter.export_notebook(notebook, export_formats=['both'])
    
    exporter.print_summary()


# Example 2: Export with custom filters
def export_with_filters(exporter, destination, min_date=None, file_types=None):
    """
    Export with custom filters
    
    Args:
        min_date: Only export pages modified after this date (ISO format)
        file_types: List of attachment types to include ['images', 'audio', 'pdf']
    """
    print(f"\n🔍 Exporting with filters...")
    
    # This would require modifying the main exporter to check dates
    # and filter attachments - shown as example structure
    
    notebooks = exporter.get_notebooks()
    exporter.export_root = Path(destination)
    
    for notebook in notebooks:
        # Custom filtering logic here
        exporter.export_notebook(notebook)


# Example 3: Export to custom format
def export_to_obsidian(exporter, destination):
    """Export in Obsidian-compatible format"""
    print("\n📝 Exporting for Obsidian...")
    
    notebooks = exporter.get_notebooks()
    export_root = Path(destination) / "Obsidian_Export"
    export_root.mkdir(exist_ok=True)
    
    for notebook in notebooks:
        notebook_folder = export_root / exporter.sanitize_filename(notebook['displayName'])
        notebook_folder.mkdir(exist_ok=True)
        
        sections = exporter.get_sections(notebook['id'])
        
        for section in sections:
            pages = exporter.get_pages(section['id'])
            
            for page in pages:
                page_content = exporter.get_page_content(page['id'])
                if not page_content:
                    continue
                
                # Convert to Obsidian-style markdown
                md_content = exporter.convert_html_to_markdown(page_content)
                
                # Add Obsidian frontmatter
                frontmatter = f"""---
title: {page['title']}
created: {page.get('createdDateTime', '')}
modified: {page.get('lastModifiedDateTime', '')}
tags: [onenote-import, {notebook['displayName'].lower().replace(' ', '-')}]
---

"""
                
                # Save as markdown
                page_file = notebook_folder / f"{exporter.sanitize_filename(page['title'])}.md"
                with open(page_file, 'w', encoding='utf-8') as f:
                    f.write(frontmatter + md_content)
    
    print(f"✅ Exported to: {export_root}")


# Example 4: Generate export report
def generate_detailed_report(exporter, destination):
    """Generate a detailed report of OneNote content"""
    print("\n📊 Generating detailed report...")
    
    notebooks = exporter.get_notebooks()
    report = {
        'total_notebooks': len(notebooks),
        'notebooks': []
    }
    
    for notebook in notebooks:
        nb_info = {
            'name': notebook['displayName'],
            'id': notebook['id'],
            'sections': []
        }
        
        sections = exporter.get_sections(notebook['id'])
        
        for section in sections:
            section_info = {
                'name': section['displayName'],
                'id': section['id'],
                'page_count': 0,
                'pages': []
            }
            
            pages = exporter.get_pages(section['id'])
            section_info['page_count'] = len(pages)
            
            for page in pages:
                page_info = {
                    'title': page['title'],
                    'created': page.get('createdDateTime', ''),
                    'modified': page.get('lastModifiedDateTime', ''),
                    'level': page.get('level', 0)
                }
                section_info['pages'].append(page_info)
            
            nb_info['sections'].append(section_info)
        
        report['notebooks'].append(nb_info)
    
    # Save report
    report_file = Path(destination) / "onenote_content_report.json"
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    print(f"✅ Report saved to: {report_file}")
    
    # Print summary
    total_sections = sum(len(nb['sections']) for nb in report['notebooks'])
    total_pages = sum(
        sum(sec['page_count'] for sec in nb['sections'])
        for nb in report['notebooks']
    )
    
    print(f"\n📈 Summary:")
    print(f"   Notebooks: {len(notebooks)}")
    print(f"   Sections: {total_sections}")
    print(f"   Total Pages: {total_pages}")


# Example 5: Export with size limits
def export_with_size_limit(exporter, destination, max_size_mb=100):
    """Export but skip very large attachments"""
    print(f"\n📦 Exporting with size limit: {max_size_mb}MB per attachment...")
    
    # This would require modifying the exporter to check file sizes
    # before downloading - shown as example structure
    
    # Modify the download_attachment method to check size:
    # if response.headers.get('content-length'):
    #     size_mb = int(response.headers['content-length']) / (1024 * 1024)
    #     if size_mb > max_size_mb:
    #         print(f"Skipping large file: {filename} ({size_mb:.1f}MB)")
    #         return False
    
    pass


# Example 6: Batch export for multiple users
def batch_export_multiple_accounts():
    """Export from multiple OneNote accounts"""
    accounts = [
        {
            'name': 'Personal',
            'client_id': 'xxx',
            'client_secret': 'xxx',
            'tenant_id': 'common'
        },
        {
            'name': 'Work',
            'client_id': 'yyy',
            'client_secret': 'yyy',
            'tenant_id': 'yyy'
        }
    ]
    
    for account in accounts:
        print(f"\n{'='*50}")
        print(f"Exporting: {account['name']}")
        print(f"{'='*50}")
        
        exporter = OneNoteExporter()
        exporter.client_id = account['client_id']
        exporter.client_secret = account['client_secret']
        exporter.tenant_id = account['tenant_id']
        
        if exporter.delegated_auth_flow():
            destination = Path.home() / "Desktop" / f"OneNote_{account['name']}"
            exporter.export_all(str(destination))


# Example 7: Dry run - preview what would be exported
def preview_export(exporter):
    """Preview export without downloading anything"""
    print("\n🔍 Preview Mode - No files will be downloaded\n")
    
    notebooks = exporter.get_notebooks()
    
    for notebook in notebooks:
        print(f"\n📓 {notebook['displayName']}")
        sections = exporter.get_sections(notebook['id'])
        
        for section in sections:
            print(f"  📑 {section['displayName']}")
            pages = exporter.get_pages(section['id'])
            print(f"     Pages: {len(pages)}")
            
            # Show first few page names
            for page in pages[:3]:
                print(f"       - {page['title']}")
            
            if len(pages) > 3:
                print(f"       ... and {len(pages) - 3} more")


# Example 8: Export only recent notes
def export_recent_notes(exporter, destination, days=30):
    """Export only notes modified in the last N days"""
    from datetime import datetime, timedelta
    
    print(f"\n📅 Exporting notes from last {days} days...")
    
    cutoff_date = datetime.now() - timedelta(days=days)
    
    notebooks = exporter.get_notebooks()
    exporter.export_root = Path(destination)
    
    recent_count = 0
    
    for notebook in notebooks:
        sections = exporter.get_sections(notebook['id'])
        
        for section in sections:
            pages = exporter.get_pages(section['id'])
            
            for page in pages:
                # Check modification date
                modified = page.get('lastModifiedDateTime', '')
                if modified:
                    modified_date = datetime.fromisoformat(modified.replace('Z', '+00:00'))
                    
                    if modified_date > cutoff_date:
                        # Export this page
                        recent_count += 1
                        # Export logic here
    
    print(f"✅ Found {recent_count} recent pages")


def main():
    """Example usage of advanced features"""
    print("="*70)
    print("OneNote Exporter - Advanced Examples")
    print("="*70)
    
    print("\nAvailable examples:")
    print("1. Export specific notebooks only")
    print("2. Export to Obsidian format")
    print("3. Generate content report")
    print("4. Preview export (dry run)")
    print("5. Export recent notes only")
    
    choice = input("\nSelect example (1-5): ").strip()
    
    # Create exporter and authenticate
    exporter = OneNoteExporter()
    if not exporter.authenticate():
        print("❌ Authentication failed")
        return
    
    destination = input("\nEnter destination path: ").strip()
    
    if choice == '1':
        notebooks = input("Enter notebook names (comma-separated): ").strip()
        notebook_list = [name.strip() for name in notebooks.split(',')]
        export_specific_notebooks(exporter, notebook_list, destination)
    
    elif choice == '2':
        export_to_obsidian(exporter, destination)
    
    elif choice == '3':
        generate_detailed_report(exporter, destination)
    
    elif choice == '4':
        preview_export(exporter)
    
    elif choice == '5':
        days = int(input("Number of days to look back: ").strip())
        export_recent_notes(exporter, destination, days)
    
    else:
        print("Invalid choice")


if __name__ == "__main__":
    main()
