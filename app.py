from flask import Flask, render_template, request, send_file, jsonify, redirect, session
from bs4 import BeautifulSoup
import os
import io
import re
import sys
import json

# Add list_to_htm to path for importing update_htm functions
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'list_to_htm'))
from update_htm import (
    parse_discount_value, generate_item_row, generate_section_header,
    generate_js_vars_full, generate_js_vars_simple, generate_js_vars_createrows,
    generate_js_if_blocks, generate_js_if_blocks_pdf, generate_js_if_blocks_whatsapp,
    update_htm
)

# Import the search functionality
sys.path.insert(0, os.path.dirname(__file__))
try:
    from search_medicines import MedicineSearcher
except ImportError as e:
    print(f"Error importing search_medicines: {e}")
    MedicineSearcher = None

def decompress_if_needed(data):
    """Auto-detect and decompress gzip data, return original bytes if not compressed."""
    try:
        return gzip_module.decompress(data)
    except (OSError, Exception):
        return data

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.secret_key = 'medicinesearch_supersecret_key'  # Needed for sessions

# Store processed results temporarily
processed_results = {}

def process_htm_content(html_content, decrease_value=1, stock_format=False, new_format=False):
    """Process HTM content and extract medicine names with discount rates."""
    soup = BeautifulSoup(html_content, "html.parser")
    results = []

    if new_format:
        # New format: <tr class="item-row"> with data-disc/data-bonus attributes
        items = soup.find_all("tr", class_="item-row")
        for item in items:
            columns = item.find_all("td")
            if len(columns) < 2:
                continue

            # Name is in td.cell-name (td[1])
            name_td = item.find("td", class_="cell-name")
            medicine_name = (name_td.text.strip() if name_td else columns[1].text.strip()).title()

            # Prefer data-disc attribute; fall back to data-bonus if disc is 0
            disc_attr = item.get("data-disc", "").strip()
            bonus_attr = item.get("data-bonus", "").strip()

            try:
                disc_num = float(disc_attr) if disc_attr else 0.0
            except ValueError:
                disc_num = 0.0

            if disc_num > 0:
                disc_num -= decrease_value
                disc_num = max(disc_num, 0)
                discount_rate = f"{disc_num:.2f}%"
            elif bonus_attr:
                discount_rate = bonus_attr
            else:
                discount_rate = "0.00%"

            results.append({'name': medicine_name, 'discount': discount_rate})

    else:
        # Default / stock format: <tr class="item">
        items = soup.find_all("tr", class_="item")
        # Column index for medicine name differs based on file format
        # Stock format: columns[2], Default format: columns[1]
        name_index = 2 if stock_format else 1

        for item in items:
            columns = item.find_all("td")
            if len(columns) >= 4:
                # Extract medicine name and apply title case
                medicine_name = columns[name_index].text.strip().title()
                discount_rate = columns[3].text.strip()

                # Check if discount is 0.00% and get bonus rate if available
                if discount_rate == "0.00%" and len(columns) >= 5:
                    discount_rate = columns[4].text.strip()

                # Extract numeric part and any additional separators
                original_discount = discount_rate
                percent_pos = original_discount.find('%')

                if percent_pos != -1:
                    # Has a percentage - extract numeric part and any separators after %
                    num_part = original_discount[:percent_pos+1]  # Include the %
                    separators = original_discount[percent_pos+1:]  # Everything after %

                    try:
                        rate_value = float(num_part.strip('%'))
                        rate_value -= decrease_value
                        rate_value = max(rate_value, 0)
                        discount_rate = f"{rate_value:.2f}%" + separators
                    except ValueError:
                        # If conversion fails, keep the original
                        discount_rate = original_discount
                else:
                    # No percentage found, treat as special case (like TP, NET, etc.)
                    try:
                        # Check if it's a numeric value without %
                        rate_value = float(original_discount)
                        rate_value -= decrease_value
                        rate_value = max(rate_value, 0)
                        discount_rate = f"{rate_value:.2f}"  # No % since original had none
                    except ValueError:
                        # Keep original value if it's not numeric
                        discount_rate = original_discount

                results.append({
                    'name': medicine_name,
                    'discount': discount_rate
                })

    return results

def generate_text_output(results, separator=','):
    """Generate text file content from results."""
    lines = []
    for item in results:
        # Check if the discount already contains a separator, if so don't add another
        discount = item['discount']
        if separator and not discount.endswith(separator):
            output_line = f"{item['name']}----- {discount}{separator}"
        else:
            output_line = f"{item['name']}----- {discount}"
        lines.append(output_line)
    return '\n'.join(lines)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/share', methods=['POST', 'GET'])
def share():
    # Handle share target from PWA
    return redirect('/?shared=true')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not file.filename.lower().endswith(('.htm', '.html')):
        return jsonify({'error': 'Please upload an HTM or HTML file'}), 400

    # Get decrease value from form (default to 1 if not provided)
    try:
        decrease_value = float(request.form.get('decrease_value', 0))
    except ValueError:
        decrease_value = 0

    # Get separator from form (default to comma)
    separator = request.form.get('separator', ',')

    # Get stock format checkbox (default to False)
    stock_format = request.form.get('stock_format', 'false').lower() == 'true'

    # Get new format checkbox (default to False)
    new_format = request.form.get('new_format', 'false').lower() == 'true'

    try:
        html_content = file.read().decode('utf-8')
    except UnicodeDecodeError:
        file.seek(0)
        html_content = file.read().decode('latin-1')

    results = process_htm_content(html_content, decrease_value, stock_format, new_format)
    text_output = generate_text_output(results, separator)

    # Store for download
    filename_base = os.path.splitext(file.filename)[0]
    output_filename = f"{filename_base}_name_with_%.txt"
    processed_results['latest'] = {
        'text': text_output,
        'filename': output_filename,
        'results': results
    }

    return jsonify({
        'success': True,
        'results': results,
        'text_output': text_output,
        'filename': output_filename,
        'count': len(results),
        'decrease_value': decrease_value
    })

@app.route('/download')
def download_file():
    if 'latest' not in processed_results:
        return "No file to download", 404

    data = processed_results['latest']
    buffer = io.BytesIO()
    buffer.write(data['text'].encode('utf-8'))
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=data['filename'],
        mimetype='text/plain'
    )

# ============ MAKE HTML FILE FUNCTIONALITY ============

def parse_text_content(text_content):
    """Parse text content (data.txt format) and return list of (item_name, discount_or_bonus)"""
    items = []
    for line in text_content.split('\n'):
        line = line.strip()
        if not line:
            continue
        if '→' in line:
            line = line.split('→', 1)[1]
        if '-----' in line:
            parts = line.split('-----')
            item_name = parts[0].strip()
            value = parts[1].strip() if len(parts) > 1 else ''
            # Preserve common separators that might be used for recognition
            # but trim extra whitespace
            value = value.strip()
            items.append((item_name, value))
    return items

def generate_html_from_template(data_items, template_path, list_no="000001", list_date=None, title="S.S.D PHARMA", whatsapp_number="923337068868"):
    """Generate HTML file from template and data items"""
    import datetime
    if list_date is None:
        list_date = datetime.datetime.now().strftime("%d/%m/%Y")

    with open(template_path, 'r', encoding='utf-8') as f:
        content = f.read()

    total_count = len(data_items)

    # Replace title everywhere
    content = content.replace('S.S.D PHARMA', title)

    # Replace WhatsApp number everywhere
    content = content.replace('923337068868', whatsapp_number)
    content = content.replace('%2B923337068868', '%2B' + whatsapp_number)

    # 1. Replace "Code" header with "Sr#"
    content = re.sub(
        r'(<td style="text-align: center; border-radius: 16px 0px 0px 0px;">)(Code|Sr#)(</td>)',
        r'\1Sr#\3',
        content
    )

    # 2. Update tbody
    tbody_start = content.find('<tbody id="myTable">')
    tbody_end = content.find('</tbody>')

    if tbody_start == -1 or tbody_end == -1:
        return None, "ERROR: Could not find tbody section in template"

    # Sort items alphabetically by name
    sorted_items = sorted(data_items, key=lambda x: x[0].upper() if x[0] else "")

    items_html = ""
    current_letter = ""
    for i, (item_name, value) in enumerate(sorted_items, 1):
        first_letter = item_name[0].upper() if item_name else "?"
        if first_letter != current_letter:
            current_letter = first_letter
            items_html += generate_section_header(current_letter)
        items_html += generate_item_row(i, item_name, value)

    items_html += f'''<tr class="heading2"> <td style=" text-align: CENTER; border-radius: 0px 0px 16px 16px; padding-left: 10px;" colspan="5" >Total Products :
  {total_count}
</td></tr>
'''

    content = content[:tbody_start + len('<tbody id="myTable">')] + items_html + content[tbody_end:]

    # 3. Update list number and date
    content = re.sub(r'<b>List No : </b>\s*\d+', f'<b>List No : </b>\n{list_no}', content)
    content = re.sub(r'<b>List Date </b> :\s*[\d/]+', f'<b>List Date </b> :\n{list_date}', content)

    # Update global list number variable for PDF generator
    content = re.sub(r'var LISTNO_GLOBAL = "[^"]*";', f'var LISTNO_GLOBAL = "{list_no}";', content)

    # Update global WhatsApp number variable
    content = re.sub(r'var WHATSAPP_GLOBAL = "[^"]*";', f'var WHATSAPP_GLOBAL = "{whatsapp_number}";', content)

    # 4. Update hidden inputs for rows count
    content = re.sub(r'id="rows" value="\d+"', f'id="rows" value="{total_count}"', content)

    # 5. Generate new JS content
    js_vars_full = generate_js_vars_full(sorted_items)
    js_vars_simple = generate_js_vars_simple(sorted_items)
    js_if_blocks_printf = generate_js_if_blocks(sorted_items, 'mywindow')
    js_if_blocks_myfun = generate_js_if_blocks(sorted_items, 'myWindow')
    js_if_whatsapp = generate_js_if_blocks_whatsapp(sorted_items)

    # 6. Update Printf function
    content = re.sub(
        r'(function Printf\(\)\{\nvar ITDATE = ")[^"]*(";\nvar LSTNO = ")[^"]*(")',
        r'\g<1>' + list_date + r'\g<2>' + list_no + r'\g<3>',
        content
    )
    content = re.sub(
        r'(function Printf\(\)\{\nvar ITDATE = "[^"]*";\nvar LSTNO = "[^"]*";\nvar custname = document\.getElementById\("cstname"\)\.value;\nvar serial = 0;\n)'
        r'.*?'
        r'(\n\n\n var mywindow = window\.open)',
        r'\1' + js_vars_full + r'\2',
        content,
        flags=re.DOTALL
    )

    content = re.sub(
        r"if\(namevar1==0 \)\{\n\}\nelse \{\n\nvar serial = \(serial\+1\);\n mywindow\.document\.write\('<tr class=\"item\">.*?"
        r"( mywindow\.document\.write\('<tr class=\"heading2\"> <td)",
        js_if_blocks_printf + r'\1',
        content,
        flags=re.DOTALL,
        count=1
    )

    # 7. Update mywht function
    content = re.sub(
        r'(function mywht\(\)\{\nvar ITDATE = ")[^"]*(";\nvar LSTNO = ")[^"]*(")',
        r'\g<1>' + list_date + r'\g<2>' + list_no + r'\g<3>',
        content
    )
    content = re.sub(
        r'(function mywht\(\)\{.*?var serial = 0;\n)'
        r'.*?'
        r'(\nvar url="https://wa\.me)',
        r'\1' + js_vars_simple + '\n' + js_if_whatsapp + r'\2',
        content,
        flags=re.DOTALL
    )

    # 8. Update myfun function
    content = re.sub(
        r'(function myfun\(\)\{\nvar ITDATE = ")[^"]*(";\nvar LSTNO = ")[^"]*(")',
        r'\g<1>' + list_date + r'\g<2>' + list_no + r'\g<3>',
        content
    )
    content = re.sub(
        r'(function myfun\(\)\{\nvar ITDATE = "[^"]*";\nvar LSTNO = "[^"]*";\nvar custname = document\.getElementById\("cstname"\)\.value;\nvar serial = 0;\n)'
        r'.*?'
        r'(\nmyWindow=window\.open)',
        r'\1' + js_vars_full + r'\2',
        content,
        flags=re.DOTALL
    )

    content = re.sub(
        r"if\(namevar1==0 \)\{\n\}\nelse \{\n\nvar serial = \(serial\+1\);\n myWindow\.document\.write\('<tr class=\"item\">.*?"
        r"( myWindow\.document\.write\('<tr class=\"heading2\"> <td)",
        js_if_blocks_myfun + r'\1',
        content,
        flags=re.DOTALL,
        count=1
    )

    # 9. Update createRows function (PDF generation)
    js_vars_createrows = generate_js_vars_createrows(sorted_items)
    js_if_blocks_pdf = generate_js_if_blocks_pdf(sorted_items)

    content = re.sub(
        r'(function createRows\(count\) \{\n  const rows = \[\];\n\n)'
        r'.*?'
        r'(var serial = 0;)',
        r'\1' + js_vars_createrows + r'\2',
        content,
        flags=re.DOTALL
    )

    content = re.sub(
        r"if\(namevar1==0 \)\{\n\}\nelse \{\n\nvar serial = \(serial\+1\);\nrows\.push.*?"
        r"(\nvar totitem=)",
        js_if_blocks_pdf + r'\1',
        content,
        flags=re.DOTALL,
        count=1
    )

    # 10. Update simpleOrder function item count
    content = re.sub(r'for \(let i = 1; i <= \d+; i\+\+\)', f'for (let i = 1; i <= {total_count}; i++)', content)

    return content, None

@app.route('/make-html')
def make_html_page():
    return render_template('make_html.html')

@app.route('/generate-html', methods=['POST'])
def generate_html():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not file.filename.lower().endswith(('.txt', '.md', '.text')):
        return jsonify({'error': 'Please upload a text file (.txt)'}), 400

    # Get form parameters
    list_no = request.form.get('list_no', '000001')
    list_date = request.form.get('list_date', None)
    title = request.form.get('title', 'S.S.D PHARMA')
    whatsapp_number = request.form.get('whatsapp_number', '923337068868')
    # Remove any non-digit characters from WhatsApp number
    whatsapp_number = ''.join(filter(str.isdigit, whatsapp_number))

    try:
        text_content = file.read().decode('utf-8')
    except UnicodeDecodeError:
        file.seek(0)
        text_content = file.read().decode('latin-1')

    # Parse text content
    data_items = parse_text_content(text_content)

    if not data_items:
        return jsonify({'error': 'No valid items found in the file. Format should be: item_name----- discount%'}), 400

    # Get template path
    template_path = os.path.join(os.path.dirname(__file__), 'list_to_htm', 'list.HTM')

    if not os.path.exists(template_path):
        return jsonify({'error': 'Template file not found'}), 500

    # Generate HTML
    html_content, error = generate_html_from_template(data_items, template_path, list_no, list_date, title, whatsapp_number)

    if error:
        return jsonify({'error': error}), 500

    # Store for download
    output_filename = f"offer_list_{list_no}.htm"
    processed_results['html_latest'] = {
        'content': html_content,
        'filename': output_filename,
        'count': len(data_items)
    }

    return jsonify({
        'success': True,
        'filename': output_filename,
        'count': len(data_items),
        'message': f'Generated HTML with {len(data_items)} items'
    })

@app.route('/download-html')
def download_html():
    if 'html_latest' not in processed_results:
        return "No file to download", 404

    data = processed_results['html_latest']
    buffer = io.BytesIO()
    buffer.write(data['content'].encode('utf-8'))
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=data['filename'],
        mimetype='text/html'
    )

@app.route('/preview-html')
def preview_html():
    if 'html_latest' not in processed_results:
        return "No HTML generated yet. Please generate HTML first.", 404

    data = processed_results['html_latest']
    return data['content']

# ============ SEARCH MEDICINES FUNCTIONALITY ============

@app.route('/search')
def search_page():
    return render_template('search.html')

import atexit
import shutil
import tempfile
import gzip as gzip_module
import time

SESSION_TTL = 300  # 5 minutes in seconds

# Global instance to store uploaded files: {session_id: {'files': [...], 'expires_at': timestamp}}
uploaded_files_storage = {}

def purge_expired_sessions():
    """Remove sessions that have passed their 5-minute TTL."""
    now = time.time()
    expired = [sid for sid, data in uploaded_files_storage.items() if data['expires_at'] < now]
    for sid in expired:
        del uploaded_files_storage[sid]

def cleanup_uploads():
    """Clean up uploaded files when the application stops"""
    upload_dir = os.path.join(tempfile.gettempdir(), 'medicine_uploads')
    if os.path.exists(upload_dir):
        # Clean all files in the uploads directory
        for filename in os.listdir(upload_dir):
            file_path = os.path.join(upload_dir, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print(f'Failed to delete {file_path}. Reason: {e}')

# Register cleanup function to run on exit
atexit.register(cleanup_uploads)

@app.route('/upload-lists', methods=['POST'])
def upload_lists():
    if 'files' not in request.files:
        return jsonify({'error': 'No files uploaded'}), 400

    files = request.files.getlist('files')
    file_paths = []

    for file in files:
        if file.filename == '':
            continue

        # Check file extension
        if not file.filename.lower().endswith(('.htm', '.html', '.txt', '.text', '.pdf')):
            continue

        # Save the file temporarily to writable temp directory (/tmp on Vercel)
        filename = file.filename
        upload_dir = os.path.join(tempfile.gettempdir(), 'medicine_uploads')
        os.makedirs(upload_dir, exist_ok=True)
        filepath = os.path.join(upload_dir, filename)

        file_data = decompress_if_needed(file.read())
        with open(filepath, 'wb') as f:
            f.write(file_data)
        file_paths.append(filepath)

    session_id = request.form.get('session_id', 'default')

    # Clean up expired sessions on each upload
    purge_expired_sessions()

    # Initialize or refresh the session with a fresh 5-minute TTL
    if session_id not in uploaded_files_storage:
        uploaded_files_storage[session_id] = {'files': [], 'expires_at': 0}

    uploaded_files_storage[session_id]['files'].extend(file_paths)
    uploaded_files_storage[session_id]['expires_at'] = time.time() + SESSION_TTL

    total_files_for_session = len(uploaded_files_storage[session_id]['files'])
    return jsonify({
        'success': True,
        'message': f'Uploaded {len(file_paths)} files, total files in session: {total_files_for_session}',
        'file_paths': uploaded_files_storage[session_id]['files'],
        'session_id': session_id,
        'expires_in': SESSION_TTL
    })

@app.route('/search-medicines', methods=['POST'])
def search_medicines():
    data = request.get_json()
    search_terms = data.get('search_terms', [])
    session_id = data.get('session_id', 'default')

    if not search_terms:
        return jsonify({'error': 'No search terms provided'}), 400

    # Get file paths for this session, checking expiry
    session_data = uploaded_files_storage.get(session_id)
    if not session_data:
        return jsonify({'error': 'Session expired or no files uploaded. Please upload your files again.', 'expired': True}), 400
    if time.time() > session_data['expires_at']:
        del uploaded_files_storage[session_id]
        return jsonify({'error': 'Session expired (5 min limit). Please upload your files again.', 'expired': True}), 400
    file_paths = session_data['files']
    if not file_paths:
        return jsonify({'error': 'No files uploaded for this session'}), 400

    # Check if MedicineSearcher is available
    if MedicineSearcher is None:
        return jsonify({'error': 'Search functionality not available, unable to import required modules'}), 500

    # Perform the search
    searcher = MedicineSearcher()
    results = searcher.search_medicines(file_paths, search_terms)

    return jsonify({
        'success': True,
        'results': results,
        'total_files': len(file_paths),
        'total_matches': sum(len(result['matches']) for result in results)
    })

if __name__ == '__main__':
    # host='0.0.0.0' allows access from other devices on same network
    app.run(debug=True, host='0.0.0.0', port=5001)
