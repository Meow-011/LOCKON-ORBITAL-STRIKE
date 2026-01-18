import os
import subprocess
from flask import Flask, request, redirect, url_for, send_from_directory, render_template_string

# สร้างโฟลเดอร์สำหรับเก็บไฟล์ที่ถูกแฮก
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# หน้าเว็บที่มีช่องโหว่
HTML_TEMPLATE = """
<!doctype html>
<title>Vulnerable File Upload</title>
<h1>Upload new File</h1>
<form method=post enctype=multipart/form-data>
  <input type=file name=file>
  <input type=submit value=Upload>
</form>
"""

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # รับไฟล์โดยไม่ตรวจอะไรเลย (Vulnerable!)
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']
        if file.filename == '':
            return 'No selected file'
        
        # บันทึกลงเครื่อง
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)
        
        # บอก Path กลับไป (เหมือนเว็บปกติ)
        return f'File uploaded successfully! Access it at <a href="/uploads/{file.filename}">here</a>'
        
    return render_template_string(HTML_TEMPLATE)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    # --- RCE SIMULATION LOGIC ---
    # ปกติ Python Web Server จะไม่รัน PHP 
    # แต่เราจะ "แกล้งทำตัว" เป็น PHP Server เพื่อทดสอบ LOCKON
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # 1. ถ้าไฟล์ลงท้ายด้วย .php (หรือ .php.jpg ตามที่เราเขียน bypass ไว้)
    if ".php" in filename:
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                content = f.read()
                
                # 2. เช็คว่าในไฟล์มีโค้ด Web Shell ของเราไหม
                # โค้ดเราคือ: <?php system($_GET['c']); ?> หรือ variations
                if "system($_GET['c'])" in content or "$_GET[c]" in content:
                    
                    # 3. ถ้ามี Parameter ?c=... ให้รันคำสั่งจริง!
                    cmd = request.args.get('c')
                    if cmd:
                        try:
                            # ⚠️ RCE ของจริง: รันคำสั่งบนเครื่องคุณผ่าน subprocess
                            # รองรับทั้ง Windows และ Linux
                            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
                            return output.decode('utf-8', errors='ignore')
                        except subprocess.CalledProcessError as e:
                            return e.output.decode('utf-8', errors='ignore')
                    
                    # ถ้าไม่มี command ก็คืนค่าว่าง หรือ echo test
                    if "echo" in content: # รองรับ Payload echo
                        return "LOCKON_RCE_CONFIRMED"
                        
        except Exception as e:
            return f"Error executing fake PHP: {e}"

    # ถ้าไม่ใช่ PHP ให้ส่งไฟล์ปกติ
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    print("🔥 Vulnerable Server Running on http://127.0.0.1:5000")
    print("⚠️  WARNING: This server allows RCE. Do not expose to public network!")
    app.run(debug=True, port=5000)