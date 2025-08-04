from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for
from flask_cors import CORS
import os
import json
import time
import psutil
import subprocess
import platform
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import threading
import uuid
import hashlib
import atexit
import signal
import shutil

# Windows Console Control Handler için
if platform.system() == "Windows":
    import ctypes
    from ctypes import wintypes


app = Flask(__name__)
CORS(app)

# 2GB maksimum dosya boyutu
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024  # 2GB
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SECRET_KEY'] = 'bluetooth-file-share-secret'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

if platform.system() == "Windows":
    try:
        import subprocess
        subprocess.run(['attrib', '+h', app.config['UPLOAD_FOLDER']], 
                      capture_output=True, check=False)
    except Exception as e:
        print(f"Windows gizleme hatası: {e}")

# Global veri depolama
devices = {}  # IP -> device info
device_uids = {}  # IP -> UID mapping
file_assignments = {}  # file_id -> {target_uid, sender_uid, filename, timestamp, path}
connected_devices = {}  # IP -> {name, uid, last_seen}

def generate_device_uid(ip_address, device_name):
    """IP ve cihaz adından benzersiz UID oluştur"""
    combined = f"{ip_address}_{device_name}_{int(time.time() // 3600)}"  # Saatlik değişim
    return hashlib.md5(combined.encode()).hexdigest()[:8].upper()

class FileManager:
    def __init__(self):
        self.cleanup_thread = threading.Thread(target=self.cleanup_old_files, daemon=True)
        self.cleanup_thread.start()
    
    def cleanup_old_files(self):
        """4 saatte bir eski dosyaları temizle"""
        while True:
            try:
                current_time = datetime.now()
                expired_files = []
                
                for file_id, file_info in file_assignments.items():
                    file_time = datetime.fromisoformat(file_info['timestamp'])
                    if current_time - file_time > timedelta(hours=4):
                        expired_files.append(file_id)
                
                for file_id in expired_files:
                    self.remove_file(file_id)
                
                time.sleep(300)  # 5 dakikada bir kontrol et
            except Exception as e:
                print(f"Cleanup error: {e}")
                time.sleep(60)
    
    def remove_file(self, file_id):
        """Dosyayı sil ve kayıttan çıkar"""
        if file_id in file_assignments:
            file_info = file_assignments[file_id]
            file_path = file_info.get('path')
            if file_path and os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    print(f"Removed expired file: {file_path}")
                except Exception as e:
                    print(f"Error removing file {file_path}: {e}")
            del file_assignments[file_id]

file_manager = FileManager()

def get_device_name_from_ip(ip):
    """IP adresinden cihaz adını almaya çalış"""
    try:
        import socket
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        # Basit cihaz adı oluştur
        ip_parts = ip.split('.')
        return f"Device-{ip_parts[-1]}"

def get_connected_devices():
    """Hotspot'a bağlı cihazları al ve UID ata"""
    devices = []
    server_ip = get_server_ip()
    
    try:
        if platform.system() == "Windows":
            # ARP tablosundan aktif cihazları al
            arp_result = subprocess.run(['arp', '-a'], capture_output=True, text=True, encoding='utf-8')
            
            for line in arp_result.stdout.split('\n'):
                if '192.168.' in line and 'dynamic' in line.lower():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        mac = parts[1].replace('-', ':').upper()
                        if mac != "FF:FF:FF:FF:FF:FF" and ip != server_ip:
                            device_name = get_device_name_from_ip(ip)
                            device_uid = generate_device_uid(ip, device_name)
                            
                            # Cihaz bilgilerini güncelle
                            connected_devices[ip] = {
                                'name': device_name,
                                'uid': device_uid,
                                'last_seen': datetime.now().isoformat()
                            }
                            
                            devices.append({
                                'ip': ip,
                                'name': device_name,
                                'uid': device_uid,
                                'mac': mac  # Görüntü için, artık kullanılmayacak
                            })
        
        # Sunucu PC'yi de listeye ekle
        try:
            import socket
            server_hostname = socket.gethostname()
            server_uid = generate_device_uid(server_ip, server_hostname)
            
            devices.append({
                'ip': server_ip,
                'name': f"💻 {server_hostname} (Server)",
                'uid': server_uid,
                'mac': get_device_mac(),
                'is_server': True
            })
            
            # Sunucu bilgilerini de kaydet
            connected_devices[server_ip] = {
                'name': f"{server_hostname} (Server)",
                'uid': server_uid,
                'last_seen': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"Server device info error: {e}")
        
        return devices
    except Exception as e:
        print(f"Error getting connected devices: {e}")
        return []

def get_server_ip():
    """Bu PC'nin aktif IP adresini al"""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def get_device_mac():
    """Bu PC'nin MAC adresini al"""
    try:
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == psutil.AF_LINK:
                    return addr.address.upper()
    except:
        pass
    return "00:00:00:00:00:00"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/devices')
def api_devices():
    """Bağlı cihazları listele"""
    devices = get_connected_devices()
    return jsonify({
        'connected_devices': devices,
        'server_ip': get_server_ip(),
        'server_mac': get_device_mac()
    })

@app.route('/api/upload-multiple', methods=['POST'])
def upload_multiple_files():
    """Çoklu dosya yükleme"""
    try:
        if 'files' not in request.files:
            return jsonify({'error': 'Dosya seçilmedi'}), 400
        
        files = request.files.getlist('files')
        target_uid = request.form.get('target_uid', '').upper()
        sender_ip = request.remote_addr
        
        if not files:
            return jsonify({'error': 'Dosya seçilmedi'}), 400
        
        if not target_uid:
            return jsonify({'error': 'Hedef cihaz UID\'si gerekli'}), 400
        
        # Toplam dosya boyutu kontrolü
        total_size = sum(file.seek(0, 2) or file.tell() for file in files)
        for file in files:  # Dosyaları başa al
            file.seek(0)
        
        if total_size > app.config['MAX_CONTENT_LENGTH']:
            return jsonify({'error': 'Toplam dosya boyutu 2GB\'ı geçemez'}), 413
        
        # Gönderen UID'sini oluştur
        sender_name = get_device_name_from_ip(sender_ip)
        sender_uid = generate_device_uid(sender_ip, sender_name)
        
        uploaded_files = []
        
        for file in files:
            if file.filename == '':
                continue
                
            # Güvenli dosya adı
            filename = secure_filename(file.filename)
            file_id = str(uuid.uuid4())
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_id}_{filename}")
            
            # Dosyayı kaydet
            file.save(file_path)
            
            # Dosya bilgilerini kaydet
            file_assignments[file_id] = {
                'target_uid': target_uid,
                'sender_uid': sender_uid,
                'sender_name': sender_name,
                'filename': filename,
                'encrypted_filename': os.path.basename(file_path),
                'timestamp': datetime.now().isoformat(),
                'path': file_path,
                'size': os.path.getsize(file_path),
                'is_encrypted': False
            }
            
            uploaded_files.append(filename)
        
        return jsonify({
            'success': True,
            'message': f'{len(uploaded_files)} dosya başarıyla kaydedildi',
            'files': uploaded_files
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Dosya seçilmedi'}), 400
        
        file = request.files['file']
        target_uid = request.form.get('target_uid', '').upper()
        sender_ip = request.remote_addr
        
        if file.filename == '':
            return jsonify({'error': 'Dosya seçilmedi'}), 400
        
        if not target_uid:
            return jsonify({'error': 'Hedef cihaz UID\'si gerekli'}), 400
        
        # Dosya boyutu kontrolü
        file.seek(0, 2)  # Dosya sonuna git
        file_size = file.tell()
        file.seek(0)  # Başa dön
        
        if file_size > app.config['MAX_CONTENT_LENGTH']:
            return jsonify({'error': 'Dosya boyutu 2GB\'ı geçemez'}), 413
        
        # Gönderen UID'sini oluştur
        sender_name = get_device_name_from_ip(sender_ip)
        sender_uid = generate_device_uid(sender_ip, sender_name)
        
        # Güvenli dosya adı
        filename = secure_filename(file.filename)
        file_id = str(uuid.uuid4())
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_id}_{filename}")
        
        # Dosyayı geçici olarak kaydet
        file.save(file_path)
        
        
        
        file_assignments[file_id] = {
            'target_uid': target_uid,
            'sender_uid': sender_uid,
            'sender_name': sender_name,
            'filename': filename,  # Orijinal dosya adı
            'encrypted_filename': os.path.basename(file_path),  # Dosya adı
            'timestamp': datetime.now().isoformat(),
            'path': file_path,
            'size': file_size,
            'is_encrypted': False 
        }
        
        return jsonify({
            'success': True,
            'file_id': file_id,
            'message': f'Dosya başarıyla kaydedildi' 
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/my-files/<device_uid>')
def get_my_files(device_uid):
    """Belirli UID'ye gönderilen dosyaları listele"""
    device_uid = device_uid.upper()
    my_files = []
    
    for file_id, file_info in file_assignments.items():
        if file_info['target_uid'] == device_uid:
            my_files.append({
                'file_id': file_id,
                'filename': file_info['filename'],  # Orijinal ad
                'sender_uid': file_info['sender_uid'],
                'sender_name': file_info.get('sender_name', 'Bilinmeyen'),
                'timestamp': file_info['timestamp'],
                'size': file_info['size'],
                'is_encrypted': file_info.get('is_encrypted', False)
            })
    
    return jsonify({'files': my_files})

@app.route('/api/sent-files/<device_uid>')
def get_sent_files(device_uid):
    """Belirli UID'den gönderilen dosyaları listele"""
    device_uid = device_uid.upper()
    sent_files = []
    
    for file_id, file_info in file_assignments.items():
        if file_info['sender_uid'] == device_uid:
            # Hedef cihaz bilgisini al
            target_device_info = None
            for ip, device_data in connected_devices.items():
                if device_data['uid'] == file_info['target_uid']:
                    target_device_info = device_data
                    break
            
            target_name = target_device_info['name'] if target_device_info else 'Bilinmeyen Cihaz'
            
            sent_files.append({
                'file_id': file_id,
                'filename': file_info['filename'],
                'target_uid': file_info['target_uid'],
                'target_name': target_name,
                'timestamp': file_info['timestamp'],
                'size': file_info['size'],
                'is_encrypted': file_info.get('is_encrypted', False)
            })
    
    return jsonify({'files': sent_files})

@app.route('/api/my-uid')
def get_my_uid():
    """İstek sahibinin UID'sini döndür"""
    client_ip = request.remote_addr
    device_name = get_device_name_from_ip(client_ip)
    device_uid = generate_device_uid(client_ip, device_name)
    
    return jsonify({
        'uid': device_uid,
        'name': device_name,
        'ip': client_ip
    })

@app.route('/api/download/<file_id>')
def download_file(file_id):
    """Dosya indirme ve otomatik şifre çözme"""
    if file_id not in file_assignments:
        return jsonify({'error': 'Dosya bulunamadı'}), 404
    
    file_info = file_assignments[file_id]
    encrypted_path = file_info['path']
    
    if not os.path.exists(encrypted_path):
        return jsonify({'error': 'Dosya mevcut değil'}), 404
    
    try:
            # Normal dosya indirme
            return send_file(encrypted_path, as_attachment=True, download_name=file_info['filename'])
            
    except Exception as e:
        print(f"Download error: {e}")
        return jsonify({'error': 'Dosya indirme hatası'}), 500

@app.route('/api/remove-file/<file_id>', methods=['DELETE'])
def remove_file(file_id):
    """Dosyayı sil - hem gönderen hem alan silebilir"""
    if file_id not in file_assignments:
        return jsonify({'error': 'Dosya bulunamadı'}), 404
    
    # İstek sahibinin UID'sini al
    client_ip = request.remote_addr
    device_name = get_device_name_from_ip(client_ip)
    client_uid = generate_device_uid(client_ip, device_name)
    
    file_info = file_assignments[file_id]
    target_uid = file_info['target_uid']
    sender_uid = file_info['sender_uid']
    
    # Yetki kontrolü: Hem gönderen hem alan silebilir
    if client_uid != target_uid and client_uid != sender_uid:
        return jsonify({'error': 'Bu dosyayı silme yetkiniz yok'}), 403
    
    file_manager.remove_file(file_id)
    return jsonify({'success': True, 'message': 'Dosya silindi'})

# Uygulama kapanırken geçici dosyaları temizle
def cleanup_uploads_folder():
    """uploads klasöründeki tüm dosyaları sil"""
    try:
        uploads_path = app.config['UPLOAD_FOLDER']
        if os.path.exists(uploads_path):
            # Windows'ta gizli özelliği kaldır
            if platform.system() == "Windows":
                try:
                    subprocess.run(['attrib', '-h', uploads_path], 
                                  capture_output=True, check=False)
                except:
                    pass
            
            # Klasördeki tüm dosyaları sil
            for filename in os.listdir(uploads_path):
                file_path = os.path.join(uploads_path, filename)
                try:
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception as e:
                    print(f"{filename} silinirken hata: {e}")
            
            
            # Windows'ta tekrar gizli yap
            if platform.system() == "Windows":
                try:
                    subprocess.run(['attrib', '+h', uploads_path], 
                                  capture_output=True, check=False)
                except:
                    pass
            
            # Global file_assignments dictionary'sini de temizle
            global file_assignments
            file_assignments.clear()
            
    except Exception as e:
        print(f"uploads klasörü temizlenirken hata: {e}")

@atexit.register
def cleanup_on_exit():
    print("Uygulama kapanıyor...")
    cleanup_uploads_folder()

def signal_handler(signum, frame):
    """Sinyal yakalandığında temizlik yap"""
    cleanup_uploads_folder()
    print("Uygulama kapatılıyor...")
    os._exit(0)

# Windows Console Control Handler
if platform.system() == "Windows":
    def windows_console_handler(ctrl_type):
        """Windows console kapatma eventi yakala"""
        if ctrl_type in (0, 1, 2, 5, 6):  # CTRL_C, CTRL_BREAK, CTRL_CLOSE, CTRL_LOGOFF, CTRL_SHUTDOWN
            print(f"\nWindows kapatma eventi ({ctrl_type}) yakalandı!")
            cleanup_uploads_folder()
            return True
        return False

    # Console handler'ı kaydet
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleCtrlHandler(
            ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)(windows_console_handler),
            True
        )
    except Exception as e:
        print(f"Windows console handler kurulum hatası: {e}")

# Sinyalleri yakala (Windows ve Unix uyumlu)
try:
    signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Terminate signal
    if hasattr(signal, 'SIGBREAK'):  # Windows
        signal.signal(signal.SIGBREAK, signal_handler)
except Exception as e:
    print(f"Signal handler kurulumu hatası: {e}")

def cleanup_at_startup():
    """Başlangıçta da temizlik yap (önceki çalışmalardan kalan dosyalar için)"""
    print("🧹 Başlangıç temizliği yapılıyor...")
    cleanup_uploads_folder()
    
    # uploads klasörünü tekrar oluştur ve gizli yap
    uploads_path = app.config['UPLOAD_FOLDER']
    os.makedirs(uploads_path, exist_ok=True)
    
    # Windows'ta gizli yap
    if platform.system() == "Windows":
        try:
            subprocess.run(['attrib', '+h', uploads_path], 
                          capture_output=True, check=False)
        except Exception as e:
            print(f"Gizleme hatası: {e}")

if __name__ == '__main__':
    print("Offline Dosya Aktarım Sunucusu Başlatılıyor...")
    print("Telefonlardan PC'nin IP adresine bağlanın")
    print("Dosyalar 4 saat sonra otomatik silinir")
    print("Maksimum dosya boyutu: 2GB")
    print(f"Server IP: {get_server_ip()}:5000")
    
    # Başlangıçta temizlik yap
    cleanup_at_startup()
    
    try:
        # Debug mode'u kapat ki signal handler'lar çalışsın
        app.run(host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        print("\nCtrl+C algılandı! Temizlik yapılıyor...")
        cleanup_uploads_folder()
    except Exception as e:
        print(f"Sunucu hatası: {e}")
        cleanup_uploads_folder()
    finally:
        print("Sunucu kapatılıyor...")
        cleanup_uploads_folder() 