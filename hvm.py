import flask
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import docker
import os
import random
import string
import json
import subprocess
import datetime
import time
import logging
import socket
import paramiko
import traceback
import shutil
import sqlite3
import threading
from dotenv import load_dotenv
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import psutil
import pty
import select
import termios
import tty
import fcntl
import struct
import signal
import uuid
import concurrent.futures
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('hvm_panel.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('HVMPanel')
# Load environment variables
load_dotenv()
# App configuration
SECRET_KEY = os.getenv('SECRET_KEY', ''.join(random.choices(string.ascii_letters + string.digits, k=32)))
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin')
PANEL_NAME = os.getenv('PANEL_NAME', 'HVM PANEL')
WATERMARK = os.getenv('WATERMARK', 'HVM VPS Service')
WELCOME_MESSAGE = os.getenv('WELCOME_MESSAGE', 'Welcome to HVM PANEL! Power Your Future!')
MAX_VPS_PER_USER = int(os.getenv('MAX_VPS_PER_USER', '3'))
DEFAULT_OS_IMAGE = os.getenv('DEFAULT_OS_IMAGE', 'ubuntu:22.04')
DOCKER_NETWORK = os.getenv('DOCKER_NETWORK', 'hvm_network')
MAX_CONTAINERS = int(os.getenv('MAX_CONTAINERS', '100'))
DB_FILE = 'hvm_panel.db'
BACKUP_FILE = 'hvm_panel_backup.json'
SERVER_IP = os.getenv('SERVER_IP', socket.gethostbyname(socket.gethostname()))
SERVER_PORT = int(os.getenv('SERVER_PORT', '3000'))
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
IMAGE_CACHE_DIR = 'image_cache'
# Known miner process names/patterns
MINER_PATTERNS = [
    'xmrig', 'ethminer', 'cgminer', 'sgminer', 'bfgminer',
    'minerd', 'cpuminer', 'cryptonight', 'stratum', 'nicehash', 'miner',
    'xmr-stak', 'ccminer', 'ewbf', 'lolminer', 'trex', 'nanominer'
]
# Dockerfile template for custom images (removed control panel support)
DOCKERFILE_TEMPLATE = """
FROM {base_image}
# Prevent prompts
ENV DEBIAN_FRONTEND=noninteractive
# Install essential packages
RUN apt-get update && \\
    apt-get install -y systemd systemd-sysv dbus sudo \\
                       curl gnupg2 apt-transport-https ca-certificates \\
                       software-properties-common \\
                       docker.io openssh-server tmate && \\
    apt-get clean && rm -rf /var/lib/apt/lists/*
# Enable SSH login with default port 22
RUN mkdir /var/run/sshd && \\
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \\
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
# Enable services on boot
RUN systemctl enable ssh && \\
    systemctl enable docker
# HVM customization (welcome and watermark set at runtime)
# Install additional packages
RUN apt-get update && \\
    apt-get install -y neofetch htop nano vim wget git tmux net-tools dnsutils iputils-ping ufw && \\
    apt-get clean && \\
    rm -rf /var/lib/apt/lists/*
# Fix systemd inside container
STOPSIGNAL SIGRTMIN+3
# Boot into systemd
CMD ["/sbin/init"]
"""

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
socketio = SocketIO(app)

ssh_clients = {}

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")
# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
# User class for authentication
class User(UserMixin):
    def __init__(self, id, username, role='user'):
        self.id = id
        self.username = username
        self.role = role
# Database class
class Database:
    def __init__(self, db_file):
        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._create_tables()
        self._initialize_settings()
        self._migrate_database()
    
    def _create_tables(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                role TEXT DEFAULT 'user',
                created_at TEXT
            )
        ''')
       
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS vps_instances (
                token TEXT PRIMARY KEY,
                vps_id TEXT UNIQUE,
                container_id TEXT,
                memory INTEGER,
                cpu INTEGER,
                disk INTEGER,
                username TEXT,
                password TEXT,
                root_password TEXT,
                created_by INTEGER,
                created_at TEXT,
                tmate_session TEXT,
                watermark TEXT,
                os_image TEXT,
                restart_count INTEGER DEFAULT 0,
                last_restart TEXT,
                status TEXT DEFAULT 'running',
                port INTEGER,
                image_id TEXT,
                expires_at TEXT,
                expires_days INTEGER DEFAULT 30,
                expires_hours INTEGER DEFAULT 0,
                expires_minutes INTEGER DEFAULT 0,
                FOREIGN KEY (created_by) REFERENCES users (id)
            )
        ''')
       
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS usage_stats (
                key TEXT PRIMARY KEY,
                value INTEGER DEFAULT 0
            )
        ''')
       
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
       
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS banned_users (
                user_id INTEGER PRIMARY KEY,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
       
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS docker_images (
                image_id TEXT PRIMARY KEY,
                os_image TEXT,
                created_at TEXT
            )
        ''')
       
        self.conn.commit()
    
    def _migrate_database(self):
        """Add new columns to existing tables for backward compatibility"""
        try:
            # Check if expires_days column exists in vps_instances table
            self.cursor.execute("PRAGMA table_info(vps_instances)")
            columns = [column[1] for column in self.cursor.fetchall()]
            
            # Add missing columns
            if 'expires_days' not in columns:
                self.cursor.execute('ALTER TABLE vps_instances ADD COLUMN expires_days INTEGER DEFAULT 30')
                print("Added expires_days column to vps_instances table")
            
            if 'expires_hours' not in columns:
                self.cursor.execute('ALTER TABLE vps_instances ADD COLUMN expires_hours INTEGER DEFAULT 0')
                print("Added expires_hours column to vps_instances table")
            
            if 'expires_minutes' not in columns:
                self.cursor.execute('ALTER TABLE vps_instances ADD COLUMN expires_minutes INTEGER DEFAULT 0')
                print("Added expires_minutes column to vps_instances table")
            
            self.conn.commit()
        except Exception as e:
            print(f"Database migration error: {e}")
            self.conn.rollback()
    
    def _initialize_settings(self):
        defaults = {
            'max_containers': str(MAX_CONTAINERS),
            'max_vps_per_user': str(MAX_VPS_PER_USER),
            'panel_name': PANEL_NAME,
            'watermark': WATERMARK,
            'welcome_message': WELCOME_MESSAGE,
            'server_ip': SERVER_IP
        }
        for key, value in defaults.items():
            self.cursor.execute('INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)', (key, value))
           
        self.cursor.execute('SELECT id FROM users WHERE username = ?', (ADMIN_USERNAME,))
        if not self.cursor.fetchone():
            hashed_password = generate_password_hash(ADMIN_PASSWORD)
            self.cursor.execute(
                'INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)',
                (ADMIN_USERNAME, hashed_password, 'admin', str(datetime.datetime.now()))
            )
           
        self.conn.commit()
    
    def get_image(self, os_image):
        self.cursor.execute('SELECT * FROM docker_images WHERE os_image = ?', (os_image,))
        row = self.cursor.fetchone()
        if row:
            columns = [desc[0] for desc in self.cursor.description]
            return dict(zip(columns, row))
        return None
    
    def add_image(self, image_data):
        columns = ', '.join(image_data.keys())
        placeholders = ', '.join('?' for _ in image_data)
        self.cursor.execute(f'INSERT INTO docker_images ({columns}) VALUES ({placeholders})', tuple(image_data.values()))
        self.conn.commit()
    
    def get_setting(self, key, default=None):
        self.cursor.execute('SELECT value FROM system_settings WHERE key = ?', (key,))
        result = self.cursor.fetchone()
        return result[0] if result else default
    
    def set_setting(self, key, value):
        self.cursor.execute('INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)', (key, str(value)))
        self.conn.commit()
    
    def get_stat(self, key, default=0):
        self.cursor.execute('SELECT value FROM usage_stats WHERE key = ?', (key,))
        result = self.cursor.fetchone()
        return result[0] if result else default
    
    def increment_stat(self, key, amount=1):
        current = self.get_stat(key)
        self.cursor.execute('INSERT OR REPLACE INTO usage_stats (key, value) VALUES (?, ?)', (key, current + amount))
        self.conn.commit()
    
    def get_user(self, username):
        self.cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        row = self.cursor.fetchone()
        if not row:
            return None
        columns = [desc[0] for desc in self.cursor.description]
        return dict(zip(columns, row))
    
    def get_user_by_id(self, user_id):
        self.cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        row = self.cursor.fetchone()
        if not row:
            return None
        columns = [desc[0] for desc in self.cursor.description]
        return dict(zip(columns, row))
    
    def create_user(self, username, password, role='user'):
        try:
            hashed_password = generate_password_hash(password)
            self.cursor.execute(
                'INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)',
                (username, hashed_password, role, str(datetime.datetime.now()))
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def update_user(self, user_id, username=None, password=None, role=None):
        updates = {}
        if username:
            updates['username'] = username
        if password:
            updates['password'] = generate_password_hash(password)
        if role:
            updates['role'] = role
        if not updates:
            return False
        set_clause = ', '.join(f'{k} = ?' for k in updates)
        values = list(updates.values()) + [user_id]
        self.cursor.execute(f'UPDATE users SET {set_clause} WHERE id = ?', values)
        self.conn.commit()
        return self.cursor.rowcount > 0
    
    def delete_user(self, user_id):
        self.cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        self.conn.commit()
        return self.cursor.rowcount > 0
    
    def get_vps_by_id(self, vps_id):
        self.cursor.execute('SELECT * FROM vps_instances WHERE vps_id = ?', (vps_id,))
        row = self.cursor.fetchone()
        if not row:
            return None, None
        columns = [desc[0] for desc in self.cursor.description]
        vps = dict(zip(columns, row))
        return vps['token'], vps
    
    def get_vps_by_token(self, token):
        self.cursor.execute('SELECT * FROM vps_instances WHERE token = ?', (token,))
        row = self.cursor.fetchone()
        if not row:
            return None
        columns = [desc[0] for desc in self.cursor.description]
        return dict(zip(columns, row))
    
    def get_user_vps_count(self, user_id):
        self.cursor.execute('SELECT COUNT(*) FROM vps_instances WHERE created_by = ?', (user_id,))
        return self.cursor.fetchone()[0]
    
    def get_user_vps(self, user_id):
        self.cursor.execute('SELECT * FROM vps_instances WHERE created_by = ?', (user_id,))
        columns = [desc[0] for desc in self.cursor.description]
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]
    
    def get_all_vps(self):
        self.cursor.execute('SELECT * FROM vps_instances')
        columns = [desc[0] for desc in self.cursor.description]
        vps_instances = {}
        for row in self.cursor.fetchall():
            vps_data = dict(zip(columns, row))
            vps_instances[vps_data['vps_id']] = vps_data
        return vps_instances
    
    def add_vps(self, vps_data):
        try:
            self.cursor.execute('''
                INSERT INTO vps_instances (
                    token, vps_id, container_id, memory, cpu, disk, username, 
                    password, root_password, created_by, created_at, tmate_session, 
                    watermark, os_image, restart_count, last_restart, status, 
                    port, image_id, expires_at, expires_days, expires_hours, expires_minutes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                vps_data.get('token'),
                vps_data.get('vps_id'),
                vps_data.get('container_id'),
                vps_data.get('memory'),
                vps_data.get('cpu'),
                vps_data.get('disk'),
                vps_data.get('username'),
                vps_data.get('password'),
                vps_data.get('root_password'),
                vps_data.get('created_by'),
                vps_data.get('created_at'),
                vps_data.get('tmate_session'),
                vps_data.get('watermark'),
                vps_data.get('os_image'),
                vps_data.get('restart_count', 0),
                vps_data.get('last_restart'),
                vps_data.get('status', 'running'),
                vps_data.get('port'),
                vps_data.get('image_id'),
                vps_data.get('expires_at'),
                vps_data.get('expires_days', 30),
                vps_data.get('expires_hours', 0),
                vps_data.get('expires_minutes', 0)
            ))
            self.conn.commit()
            self.increment_stat('total_vps_created')
            return True
        except sqlite3.Error as e:
            print(f"Error adding VPS: {e}")
            return False
    
    def remove_vps(self, token):
        self.cursor.execute('DELETE FROM vps_instances WHERE token = ?', (token,))
        self.conn.commit()
        return self.cursor.rowcount > 0
    
    def update_vps(self, token, updates):
        try:
            set_clause = ', '.join(f'{k} = ?' for k in updates)
            values = list(updates.values()) + [token]
            self.cursor.execute(f'UPDATE vps_instances SET {set_clause} WHERE token = ?', values)
            self.conn.commit()
            return self.cursor.rowcount > 0
        except sqlite3.Error as e:
            print(f"Error updating VPS: {e}")
            return False
    
    def is_user_banned(self, user_id):
        self.cursor.execute('SELECT 1 FROM banned_users WHERE user_id = ?', (user_id,))
        return self.cursor.fetchone() is not None
    
    def ban_user(self, user_id):
        self.cursor.execute('INSERT OR IGNORE INTO banned_users (user_id) VALUES (?)', (user_id,))
        self.conn.commit()
    
    def unban_user(self, user_id):
        self.cursor.execute('DELETE FROM banned_users WHERE user_id = ?', (user_id,))
        self.conn.commit()
    
    def get_banned_users(self):
        self.cursor.execute('SELECT user_id FROM banned_users')
        return [row[0] for row in self.cursor.fetchall()]
    
    def get_all_users(self):
        self.cursor.execute('SELECT id, username, role, created_at FROM users')
        columns = [desc[0] for desc in self.cursor.description]
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]
    
    def update_user_role(self, user_id, role):
        self.cursor.execute('UPDATE users SET role = ? WHERE id = ?', (role, user_id))
        self.conn.commit()
        return self.cursor.rowcount > 0
    
    def backup_data(self):
        data = {
            'vps_instances': list(self.get_all_vps().values()),
            'usage_stats': {},
            'system_settings': {},
            'banned_users': self.get_banned_users(),
            'users': self.get_all_users(),
            'docker_images': []
        }
       
        self.cursor.execute('SELECT * FROM usage_stats')
        for row in self.cursor.fetchall():
            data['usage_stats'][row[0]] = row[1]
           
        self.cursor.execute('SELECT * FROM system_settings')
        for row in self.cursor.fetchall():
            data['system_settings'][row[0]] = row[1]
           
        self.cursor.execute('SELECT * FROM docker_images')
        columns = [desc[0] for desc in self.cursor.description]
        data['docker_images'] = [dict(zip(columns, row)) for row in self.cursor.fetchall()]
           
        with open(BACKUP_FILE, 'w') as f:
            json.dump(data, f, indent=4)
           
        return True
    
    def restore_data(self):
        if not os.path.exists(BACKUP_FILE):
            return False
           
        try:
            with open(BACKUP_FILE, 'r') as f:
                data = json.load(f)
               
            self.cursor.execute('DELETE FROM vps_instances')
            self.cursor.execute('DELETE FROM usage_stats')
            self.cursor.execute('DELETE FROM system_settings')
            self.cursor.execute('DELETE FROM banned_users')
            self.cursor.execute('DELETE FROM users')
            self.cursor.execute('DELETE FROM docker_images')
           
            for user in data.get('users', []):
                self.cursor.execute(
                    'INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)',
                    (user['username'], user.get('password', generate_password_hash('defaultpass')), user['role'], user['created_at'])
                )
           
            for vps in data.get('vps_instances', []):
                columns = ', '.join(vps.keys())
                placeholders = ', '.join('?' for _ in vps)
                self.cursor.execute(f'INSERT INTO vps_instances ({columns}) VALUES ({placeholders})', tuple(vps.values()))
           
            for key, value in data.get('usage_stats', {}).items():
                self.cursor.execute('INSERT INTO usage_stats (key, value) VALUES (?, ?)', (key, value))
               
            for key, value in data.get('system_settings', {}).items():
                self.cursor.execute('INSERT INTO system_settings (key, value) VALUES (?, ?)', (key, value))
               
            for user_id in data.get('banned_users', []):
                self.cursor.execute('INSERT INTO banned_users (user_id) VALUES (?)', (user_id,))
               
            for image in data.get('docker_images', []):
                columns = ', '.join(image.keys())
                placeholders = ', '.join('?' for _ in image)
                self.cursor.execute(f'INSERT INTO docker_images ({columns}) VALUES ({placeholders})', tuple(image.values()))
               
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error restoring data: {e}")
            return False
    
    def close(self):
        self.conn.close()

# Initialize database
db = Database(DB_FILE)

# Initialize Docker client
try:
    docker_client = docker.from_env()
    # Create Docker network if it doesn't exist
    try:
        docker_client.networks.create(DOCKER_NETWORK, check_duplicate=True)
    except docker.errors.APIError:
        pass
    logger.info("Docker client initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Docker client: {e}")
    docker_client = None

# System stats
system_stats = {
    'cpu_usage': 0,
    'memory_usage': 0,
    'disk_usage': 0,
    'network_io': (0, 0),
    'last_updated': 0
}

# VPS stats cache
vps_stats_cache = {}

# Console sessions
console_sessions = {}

# Image build lock
image_build_lock = threading.Lock()

# Helper functions
def generate_token():
    return str(uuid.uuid4())

def generate_vps_id():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))

def generate_ssh_password():
    chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    return ''.join(random.choices(chars, k=20))

def is_admin(user):
    user_data = db.get_user_by_id(user.id)
    return user_data and user_data['role'] == 'admin'

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not is_admin(current_user):
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def run_command(command, timeout=30):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)

def run_docker_command(container_id, command, timeout=30):
    try:
        result = subprocess.run(
            ["docker", "exec", container_id] + command,
            capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)

def update_system_stats():
    global system_stats
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        net_io = psutil.net_io_counters()
        connections = len(psutil.net_connections())
       
        system_stats = {
            'cpu_usage': cpu_percent,
            'memory_usage': mem.percent,
            'memory_used': mem.used / (1024 ** 3),
            'memory_total': mem.total / (1024 ** 3),
            'disk_usage': disk.percent,
            'disk_used': disk.used / (1024 ** 3),
            'disk_total': disk.total / (1024 ** 3),
            'network_sent': net_io.bytes_sent / (1024 ** 2),
            'network_recv': net_io.bytes_recv / (1024 ** 2),
            'active_connections': connections,
            'last_updated': time.time()
        }
    except Exception as e:
        logger.error(f"Error updating system stats: {e}")

def update_vps_stats():
    global vps_stats_cache
    try:
        for token, vps in db.get_all_vps().items():
            if vps['status'] != 'running':
                vps_stats_cache[vps['vps_id']] = {'status': vps['status']}
                continue
            try:
                container = docker_client.containers.get(vps['container_id'])
                stats = container.stats(stream=False)
                memory_stats = stats['memory_stats']
                cpu_stats = stats['cpu_stats']
                memory_usage = memory_stats.get('usage', 0) / (1024 ** 2)
                memory_limit = memory_stats.get('limit', vps['memory'] * 1024 ** 2) / (1024 ** 2)
                cpu_usage = (cpu_stats['cpu_usage']['total_usage'] / cpu_stats['system_cpu_usage']) * 100 if cpu_stats.get('system_cpu_usage') else 0
                vps_stats_cache[vps['vps_id']] = {
                    'cpu_percent': round(cpu_usage, 2),
                    'memory_percent': round((memory_usage / memory_limit) * 100, 2) if memory_limit else 0,
                    'status': 'running'
                }
            except:
                vps_stats_cache[vps['vps_id']] = {'status': 'error'}
    except Exception as e:
        logger.error(f"Error updating VPS stats: {e}")

def build_custom_image(base_image=DEFAULT_OS_IMAGE):
    with image_build_lock:
        existing_image = db.get_image(base_image)
        if existing_image:
            try:
                docker_client.images.get(existing_image['image_id'])
                logger.info(f"Reusing existing image {existing_image['image_id']}")
                return existing_image['image_id']
            except docker.errors.ImageNotFound:
                db.cursor.execute('DELETE FROM docker_images WHERE os_image = ?', (base_image,))
                db.conn.commit()
       
        try:
            os.makedirs(IMAGE_CACHE_DIR, exist_ok=True)
            temp_dir = os.path.join(IMAGE_CACHE_DIR, base_image.replace(':', '-'))
            os.makedirs(temp_dir, exist_ok=True)
           
            dockerfile_content = DOCKERFILE_TEMPLATE.format(
                base_image=base_image
            )
           
            dockerfile_path = os.path.join(temp_dir, "Dockerfile")
            with open(dockerfile_path, 'w') as f:
                f.write(dockerfile_content)
           
            image_tag = f"hvm/{base_image.replace(':', '-').lower()}:latest"
            image, build_logs = docker_client.images.build(
                path=temp_dir,
                tag=image_tag,
                rm=True,
                forcerm=True,
                quiet=False
            )
           
            for log in build_logs:
                if 'stream' in log:
                    logger.info(log['stream'].strip())
           
            # Store image info in database
            image_data = {
                'image_id': image_tag,
                'os_image': base_image,
                'created_at': str(datetime.datetime.now())
            }
            db.add_image(image_data)
           
            return image_tag
        except docker.errors.BuildError as e:
            for line in e.build_log:
                if 'stream' in line:
                    logger.error(line['stream'].strip())
            raise Exception(f"Failed to build image: {e}")
        except Exception as e:
            logger.error(f"Error building custom image: {e}")
            raise
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)

def setup_container(container_id, memory, vps_id, ssh_port, root_password):
    try:
        container = docker_client.containers.get(container_id)
        if container.status != "running":
            container.start()
            time.sleep(5)
       
        # Set root password
        success, stdout, stderr = run_docker_command(container_id, ["bash", "-c", f"echo 'root:{root_password}' | chpasswd"])
        if not success:
            raise Exception(f"Failed to set root password: {stderr}")
       
        # Set welcome message
        welcome_cmd = f"echo '{db.get_setting('welcome_message', WELCOME_MESSAGE)}' > /etc/motd && echo 'echo \"{db.get_setting('welcome_message', WELCOME_MESSAGE)}\"' >> /root/.bashrc"
        success, stdout, stderr = run_docker_command(container_id, ["bash", "-c", welcome_cmd])
        if not success:
            logger.warning(f"Could not set welcome message: {stderr}")
       
        # Set hostname
        hostname_cmd = f"echo 'hvm-{vps_id}' > /etc/hostname && hostname hvm-{vps_id}"
        success, stdout, stderr = run_docker_command(container_id, ["bash", "-c", hostname_cmd])
        if not success:
            raise Exception(f"Failed to set hostname: {stderr}")
       
        # Set watermark
        success, stdout, stderr = run_docker_command(container_id, ["bash", "-c", f"echo '{db.get_setting('watermark', WATERMARK)}' > /etc/machine-info"])
        if not success:
            logger.warning(f"Could not set machine info: {stderr}")
       
        # Security setup
        security_commands = [
            "apt-get update && apt-get upgrade -y",
            "ufw allow 22",
            "ufw --force enable",
            "apt-get -y autoremove",
            "apt-get clean",
            "chmod 700 /root"
        ]
       
        for cmd in security_commands:
            success, stdout, stderr = run_docker_command(container_id, ["bash", "-c", cmd])
            if not success:
                logger.warning(f"Security setup command failed: {cmd} - {stderr}")
       
        return True, vps_id
    except Exception as e:
        error_msg = f"Setup failed: {str(e)}"
        logger.error(error_msg)
        return False, None

def get_tmate_session(container_id):
    try:
        process = subprocess.Popen(
            ["docker", "exec", container_id, "tmate", "-F"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
       
        start_time = time.time()
        session = None
        while time.time() - start_time < 10:
            line = process.stdout.readline()
            if "ssh session:" in line:
                session = line.split("ssh session:")[1].strip()
                break
       
        process.terminate()
        return session
    except Exception as e:
        logger.error(f"Error getting tmate session: {e}")
        return None
# Flask routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
   
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
       
        if not username or not password:
            return render_template('login.html', error='Missing credentials', panel_name=PANEL_NAME)
       
        user_data = db.get_user(username)
        if user_data and check_password_hash(user_data['password'], password):
            if db.is_user_banned(user_data['id']):
                logger.warning(f"Banned user {username} attempted login")
                return render_template('login.html', error='Your account is banned', panel_name=PANEL_NAME)
            user = User(user_data['id'], user_data['username'], user_data['role'])
            login_user(user)
            logger.info(f"User {username} logged in successfully")
            return redirect(url_for('dashboard'))
       
        logger.warning(f"Failed login attempt for {username}")
        return render_template('login.html', error='Invalid credentials', panel_name=PANEL_NAME)
   
    return render_template('login.html', panel_name=PANEL_NAME)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
   
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
       
        if not username or not password or not confirm_password:
            return render_template('register.html', error='All fields are required', panel_name=PANEL_NAME)
       
        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match', panel_name=PANEL_NAME)
       
        if len(password) < 12:
            return render_template('register.html', error='Password must be at least 12 characters', panel_name=PANEL_NAME)
       
        if db.create_user(username, password):
            logger.info(f"New user {username} registered")
            return redirect(url_for('login'))
       
        return render_template('register.html', error='Username already exists', panel_name=PANEL_NAME)
   
    return render_template('register.html', panel_name=PANEL_NAME)
@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    logger.info(f"User {username} logged out")
    return redirect(url_for('login'))
@app.route('/dashboard')
@login_required
def dashboard():
    if db.is_user_banned(current_user.id):
        logout_user()
        return render_template('login.html', error='Your account is banned', panel_name=PANEL_NAME)
   
    user_vps = db.get_user_vps(current_user.id)
    return render_template('dashboard.html',
                         vps_list=user_vps,
                         panel_name=db.get_setting('panel_name', PANEL_NAME),
                         server_ip=db.get_setting('server_ip', SERVER_IP),
                         is_admin=is_admin(current_user))
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        user_data = db.get_user_by_id(current_user.id)
        if not check_password_hash(user_data['password'], current_password):
            return render_template('profile.html', error='Incorrect current password', panel_name=PANEL_NAME)
        
        if new_password != confirm_password:
            return render_template('profile.html', error='New passwords do not match', panel_name=PANEL_NAME)
        
        if len(new_password) < 12:
            return render_template('profile.html', error='New password must be at least 12 characters', panel_name=PANEL_NAME)
        
        db.update_user(current_user.id, password=new_password)
        logger.info(f"User {current_user.username} updated password")
        return render_template('profile.html', success='Password updated successfully', panel_name=PANEL_NAME)
    
    return render_template('profile.html', panel_name=PANEL_NAME)
@app.route('/create_vps', methods=['GET', 'POST'])
@login_required
@admin_required
def create_vps():
    if not docker_client:
        return render_template('error.html', error='Docker is not available. Please contact the administrator.', panel_name=PANEL_NAME)
   
    if request.method == 'POST':
        try:
            memory = int(request.form.get('memory', 1))
            cpu = int(request.form.get('cpu', 1))
            disk = int(request.form.get('disk', 10))
            os_image = request.form.get('os_image', DEFAULT_OS_IMAGE)
            user_id = current_user.id
            
            # Get expiration time (default to 30 days if not provided)
            expires_days = int(request.form.get('expires_days', 30))
            expires_hours = int(request.form.get('expires_hours', 0))
            expires_minutes = int(request.form.get('expires_minutes', 0))
            
            if is_admin(current_user):
                user_id = int(request.form.get('user_id', current_user.id))
        except ValueError:
            return render_template('create_vps.html', error='Invalid input values', panel_name=PANEL_NAME)
       
        if not db.get_user_by_id(user_id):
            return render_template('create_vps.html', error='Invalid user selected', panel_name=PANEL_NAME)
       
        if memory < 1 or memory > 512:
            return render_template('create_vps.html', error='Memory must be between 1GB and 512GB', panel_name=PANEL_NAME)
        if cpu < 1 or cpu > 32:
            return render_template('create_vps.html', error='CPU cores must be between 1 and 32', panel_name=PANEL_NAME)
        if disk < 10 or disk > 1000:
            return render_template('create_vps.html', error='Disk space must be between 10GB and 1000GB', panel_name=PANEL_NAME)
        
        # Validate expiration time
        total_minutes = (expires_days * 24 * 60) + (expires_hours * 60) + expires_minutes
        if total_minutes <= 0:
            return render_template('create_vps.html', error='Expiration time must be greater than 0', panel_name=PANEL_NAME)
        if expires_days > 365:
            return render_template('create_vps.html', error='Expiration time cannot exceed 365 days', panel_name=PANEL_NAME)
       
        if db.get_user_vps_count(user_id) >= int(db.get_setting('max_vps_per_user', MAX_VPS_PER_USER)):
            return render_template('create_vps.html', error=f'User has reached the maximum limit of {db.get_setting("max_vps_per_user")} VPS instances', panel_name=PANEL_NAME)
       
        containers = docker_client.containers.list(all=True)
        if len(containers) >= int(db.get_setting('max_containers', MAX_CONTAINERS)):
            return render_template('create_vps.html', error=f'Maximum container limit reached ({db.get_setting("max_containers")}). Please try again later.', panel_name=PANEL_NAME)
       
        vps_id = generate_vps_id()
        token = generate_token()
        root_password = generate_ssh_password()
       
        used_ports = set(v['port'] for v in db.get_all_vps().values() if v.get('port'))
        ssh_port = random.randint(20000, 30000)
        while ssh_port in used_ports:
            ssh_port = random.randint(20000, 30000)
       
        try:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(build_custom_image, os_image)
                image_tag = future.result(timeout=300)  # 5 minute timeout
        except Exception as e:
            logger.error(f"Failed to build image for VPS {vps_id}: {str(e)}")
            return render_template('create_vps.html', error=f'Failed to build Docker image: {str(e)}', panel_name=PANEL_NAME)
       
        container = None
        ports = {'22/tcp': ssh_port}
       
        try:
            container = docker_client.containers.run(
                image_tag,
                detach=True,
                privileged=True,
                hostname=f"hvm-{vps_id}",
                mem_limit=memory * 1024 * 1024 * 1024,
                cpu_period=100000,
                cpu_quota=int(cpu * 100000),
                cap_add=["SYS_ADMIN", "NET_ADMIN"],
                security_opt=["seccomp=unconfined"],
                network=DOCKER_NETWORK,
                volumes={
                    f'hvm-{vps_id}': {'bind': '/data', 'mode': 'rw'}
                },
                restart_policy={"Name": "always"},
                ports=ports
            )
        except Exception as e:
            logger.error(f"Failed to start container for VPS {vps_id}: {str(e)}")
            if container:
                container.remove()
            try:
                docker_client.images.remove(image_tag)
            except:
                pass
            return render_template('create_vps.html', error=f'Failed to start container: {str(e)}', panel_name=PANEL_NAME)
       
        time.sleep(5)
       
        container.reload()
        if '22/tcp' not in container.ports or not container.ports['22/tcp']:
            container.stop()
            container.remove()
            try:
                docker_client.images.remove(image_tag)
            except:
                pass
            return render_template('create_vps.html', error='Failed to assign SSH port', panel_name=PANEL_NAME)
       
        setup_success, final_vps_id = setup_container(
            container.id,
            memory,
            vps_id,
            ssh_port,
            root_password
        )
       
        if not setup_success:
            container.stop()
            container.remove()
            try:
                docker_client.images.remove(image_tag)
            except:
                pass
            return render_template('create_vps.html', error='Failed to setup container', panel_name=PANEL_NAME)
       
        tmate_session = get_tmate_session(container.id)
        
        # Calculate expiration time
        expires_at = datetime.datetime.now() + datetime.timedelta(
            days=expires_days,
            hours=expires_hours,
            minutes=expires_minutes
        )
       
        vps_data = {
            "token": token,
            "vps_id": final_vps_id,
            "container_id": container.id,
            "memory": memory,
            "cpu": cpu,
            "disk": disk,
            "username": "root",
            "password": root_password,
            "root_password": root_password,
            "created_by": user_id,
            "created_at": str(datetime.datetime.now()),
            "tmate_session": tmate_session,
            "watermark": db.get_setting('watermark', WATERMARK),
            "os_image": os_image,
            "restart_count": 0,
            "last_restart": None,
            "status": "running",
            "port": ssh_port,
            "image_id": image_tag,
            "expires_at": str(expires_at),
            "expires_days": expires_days,
            "expires_hours": expires_hours,
            "expires_minutes": expires_minutes
        }
       
        db.add_vps(vps_data)
        logger.info(f"VPS {final_vps_id} created for user {user_id} with expiration at {expires_at}")
       
        return render_template('vps_created.html', vps=vps_data, server_ip=db.get_setting('server_ip', SERVER_IP), panel_name=PANEL_NAME)
   
    available_os_images = ['ubuntu:22.04', 'ubuntu:24.04', 'ubuntu:20.04', 'debian:12', 'debian:11']
    all_users = db.get_all_users() if is_admin(current_user) else None
    return render_template('create_vps.html', os_images=available_os_images, users=all_users, panel_name=PANEL_NAME)
    
@app.route('/edit_vps/<vps_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_vps(vps_id):
    token, vps = db.get_vps_by_id(vps_id)
    if not vps:
        return render_template('error.html', error='VPS not found', panel_name=PANEL_NAME)
   
    if request.method == 'POST':
        try:
            new_memory = int(request.form.get('memory', vps['memory']))
            new_cpu = int(request.form.get('cpu', vps['cpu']))
            new_disk = int(request.form.get('disk', vps['disk']))
            new_user_id = int(request.form.get('user_id', vps['created_by']))
            new_os_image = request.form.get('os_image', vps['os_image'])
        except ValueError:
            return render_template('edit_vps.html', error='Invalid input values', vps=vps, panel_name=PANEL_NAME)
       
        # Validate user exists
        if not db.get_user_by_id(new_user_id):
            return render_template('edit_vps.html', error='Invalid user selected', vps=vps, panel_name=PANEL_NAME)
       
        if new_memory < 1 or new_memory > 512 or new_cpu < 1 or new_cpu > 32 or new_disk < 10 or new_disk > 1000:
            return render_template('edit_vps.html', error='Invalid resource values', vps=vps, panel_name=PANEL_NAME)
       
        # Check if user has reached VPS limit (only if changing user)
        if new_user_id != vps['created_by']:
            if db.get_user_vps_count(new_user_id) >= int(db.get_setting('max_vps_per_user', MAX_VPS_PER_USER)):
                return render_template('edit_vps.html', error=f'Selected user has reached the maximum limit of {db.get_setting("max_vps_per_user")} VPS instances', vps=vps, panel_name=PANEL_NAME)
       
        if new_os_image != vps['os_image']:
            was_running = vps['status'] == 'running'
            container = docker_client.containers.get(vps['container_id'])
            if was_running:
                container.stop()
           
            try:
                new_image_tag = build_custom_image(new_os_image)
            except Exception as e:
                if was_running:
                    container.start()
                return render_template('edit_vps.html', error=f'Failed to build new image: {str(e)}', vps=vps, panel_name=PANEL_NAME)
           
            container.remove()
           
            ports = {'22/tcp': vps['port']}
           
            try:
                new_container = docker_client.containers.run(
                    new_image_tag,
                    detach=True,
                    privileged=True,
                    hostname=f"hvm-{vps['vps_id']}",
                    mem_limit=new_memory * 1024 * 1024 * 1024,
                    cpu_period=100000,
                    cpu_quota=int(new_cpu * 100000),
                    cap_add=["SYS_ADMIN", "NET_ADMIN"],
                    security_opt=["seccomp=unconfined"],
                    network=DOCKER_NETWORK,
                    volumes={
                        f'hvm-{vps["vps_id"]}': {'bind': '/data', 'mode': 'rw'}
                    },
                    restart_policy={"Name": "always"},
                    ports=ports
                )
            except Exception as e:
                return render_template('edit_vps.html', error=f'Failed to start new container: {str(e)}', vps=vps, panel_name=PANEL_NAME)
           
            time.sleep(5)
           
            new_container.reload()
           
            setup_success, _ = setup_container(new_container.id, new_memory, vps['vps_id'], vps['port'], vps['root_password'])
            if not setup_success:
                new_container.stop()
                new_container.remove()
                return render_template('edit_vps.html', error='Failed to setup new container', vps=vps, panel_name=PANEL_NAME)
           
            updates = {
                'container_id': new_container.id,
                'memory': new_memory,
                'cpu': new_cpu,
                'disk': new_disk,
                'os_image': new_os_image,
                'created_by': new_user_id,  # Added user change
                'status': 'running',
                'image_id': new_image_tag
            }
            db.update_vps(token, updates)
           
            try:
                if vps['image_id'] != new_image_tag:
                    docker_client.images.remove(vps['image_id'])
            except:
                pass
           
        else:
            container = docker_client.containers.get(vps['container_id'])
            was_running = container.status == "running"
            if was_running:
                container.stop()
           
            container.update(
                mem_limit=new_memory * 1024 * 1024 * 1024,
                cpu_quota=int(new_cpu * 100000),
                cpu_period=100000
            )
           
            if was_running:
                container.start()
           
            updates = {
                'memory': new_memory,
                'cpu': new_cpu,
                'disk': new_disk,
                'created_by': new_user_id,  # Added user change
                'status': 'running'
            }
            db.update_vps(token, updates)
       
        logger.info(f"VPS {vps_id} edited by admin {current_user.username}, assigned to user ID {new_user_id}")
        return redirect(url_for('admin_panel'))
   
    available_os_images = ['ubuntu:22.04', 'ubuntu:24.04', 'ubuntu:20.04', 'debian:12', 'debian:11']
    all_users = db.get_all_users()  # Get all users for the dropdown
    return render_template('edit_vps.html', vps=vps, os_images=available_os_images, users=all_users, panel_name=PANEL_NAME)
@app.route('/vps/<vps_id>')
@login_required
def vps_details(vps_id):
    token, vps = db.get_vps_by_id(vps_id)
    if not vps or (vps['created_by'] != current_user.id and not is_admin(current_user)):
        return render_template('error.html', error='VPS not found or access denied', panel_name=PANEL_NAME)
   
    try:
        container = docker_client.containers.get(vps['container_id'])
        container_status = container.status
    except:
        container_status = 'not_found'
   
    return render_template(
        'vps_details.html',
        vps=vps,
        container_status=container_status,
        server_ip=db.get_setting('server_ip', SERVER_IP),
        panel_name=PANEL_NAME
    )
@app.route('/vps/<vps_id>/start')
@login_required
def start_vps(vps_id):
    token, vps = db.get_vps_by_id(vps_id)
    if not vps or (vps['created_by'] != current_user.id and not is_admin(current_user)):
        return jsonify({'error': 'VPS not found or access denied'}), 404
   
    try:
        container = docker_client.containers.get(vps['container_id'])
        if container.status == "running":
            return jsonify({'error': 'VPS is already running'}), 400
       
        container.start()
        db.update_vps(token, {'status': 'running'})
        logger.info(f"VPS {vps_id} started by user {current_user.username}")
        return jsonify({'message': 'VPS started successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/vps/<vps_id>/stop')
@login_required
def stop_vps(vps_id):
    token, vps = db.get_vps_by_id(vps_id)
    if not vps or (vps['created_by'] != current_user.id and not is_admin(current_user)):
        return jsonify({'error': 'VPS not found or access denied'}), 404
   
    try:
        container = docker_client.containers.get(vps['container_id'])
        if container.status != "running":
            return jsonify({'error': 'VPS is already stopped'}), 400
       
        container.stop()
        db.update_vps(token, {'status': 'stopped'})
        logger.info(f"VPS {vps_id} stopped by user {current_user.username}")
        return jsonify({'message': 'VPS stopped successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/vps/<vps_id>/restart')
@login_required
def restart_vps(vps_id):
    token, vps = db.get_vps_by_id(vps_id)
    if not vps or (vps['created_by'] != current_user.id and not is_admin(current_user)):
        return jsonify({'error': 'VPS not found or access denied'}), 404
   
    try:
        container = docker_client.containers.get(vps['container_id'])
        container.restart()
       
        updates = {
            'restart_count': vps.get('restart_count', 0) + 1,
            'last_restart': str(datetime.datetime.now()),
            'status': 'running',
            'port': vps['port'] # Ensure port persists
        }
        db.update_vps(token, updates)
       
        tmate_session = get_tmate_session(container.id)
        if tmate_session:
            db.update_vps(token, {'tmate_session': tmate_session})
       
        logger.info(f"VPS {vps_id} restarted by user {current_user.username}")
        return jsonify({'message': 'VPS restarted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/vps/<vps_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_vps(vps_id):
    token, vps = db.get_vps_by_id(vps_id)
    if not vps or (vps['created_by'] != current_user.id and not is_admin(current_user)):
        return render_template('error.html', error='VPS not found or access denied', panel_name=PANEL_NAME)
   
    if request.method == 'POST':
        try:
            container = docker_client.containers.get(vps['container_id'])
            container.stop()
            container.remove()
            try:
                volume = docker_client.volumes.get(f'hvm-{vps["vps_id"]}')
                volume.remove()
            except:
                pass
        except:
            pass
       
        db.remove_vps(token)
        logger.info(f"VPS {vps_id} deleted by user {current_user.username}")
        return jsonify({'message': 'VPS deleted successfully'})
   
    return render_template('confirm_delete.html', vps_id=vps_id, panel_name=PANEL_NAME)
@app.route('/vps/<vps_id>/renew')
@login_required
@admin_required
def renew_vps(vps_id):
    token, vps = db.get_vps_by_id(vps_id)
    if not vps:
        return jsonify({'error': 'VPS not found'}), 404
   
    try:
        new_expires = datetime.datetime.strptime(vps['expires_at'], '%Y-%m-%d %H:%M:%S.%f') + datetime.timedelta(days=30)
        db.update_vps(token, {'expires_at': str(new_expires)})
       
        if vps['status'] == 'expired':
            container = docker_client.containers.get(vps['container_id'])
            container.start()
            db.update_vps(token, {'status': 'running'})
       
        logger.info(f"VPS {vps_id} renewed by admin {current_user.username}")
        return jsonify({'message': 'VPS renewed successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/vps/<vps_id>/console')
@login_required
def vps_console(vps_id):
    # Access check
    token, vps = db.get_vps_by_id(vps_id)
    if not vps or (vps['created_by'] != current_user.id and not is_admin(current_user)):
        return render_template('error.html', error='VPS not found or access denied', panel_name=PANEL_NAME)

    return render_template("console.html", vps=vps, panel_name=PANEL_NAME)

@socketio.on('ssh_connect')
def ssh_connect(data):
    sid = request.sid
    host = data.get('host')
    port = int(data.get('port', 22))
    username = data.get('username')
    password = data.get('password')

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=port, username=username, password=password, timeout=10)

        chan = ssh.invoke_shell(term='xterm')
        ssh_clients[sid] = (ssh, chan)

        def forward_output():
            while True:
                try:
                    data = chan.recv(1024)
                    if not data:
                        break
                    socketio.emit('ssh_output', data.decode(errors='ignore'), room=sid)
                except Exception:
                    break

        threading.Thread(target=forward_output, daemon=True).start()
        emit('ssh_output', f"\n✅ Connected to {host}:{port} as {username}\n")

    except Exception as e:
        emit('ssh_output', f"\n❌ Connection failed: {str(e)}\n")

@socketio.on('ssh_input')
def ssh_input(data):
    sid = request.sid
    if sid in ssh_clients:
        ssh, chan = ssh_clients[sid]
        try:
            chan.send(data)
        except Exception:
            emit('ssh_output', "\n❌ Error sending data\n")

@socketio.on('disconnect')
def disconnect():
    sid = request.sid
    if sid in ssh_clients:
        ssh, chan = ssh_clients[sid]
        chan.close()
        ssh.close()
        del ssh_clients[sid]

   
    return render_template('vps_console.html', vps=vps, panel_name=PANEL_NAME)
@app.route('/vps/<vps_id>/stats')
@login_required
def vps_stats(vps_id):
    token, vps = db.get_vps_by_id(vps_id)
    if not vps or (vps['created_by'] != current_user.id and not is_admin(current_user)):
        return jsonify({'error': 'VPS not found or access denied'}), 404
   
    try:
        container = docker_client.containers.get(vps['container_id'])
        if container.status != "running":
            return jsonify({'error': 'VPS is not running'}), 400
       
        stats = container.stats(stream=False)
       
        memory_stats = stats['memory_stats']
        cpu_stats = stats['cpu_stats']
        blkio_stats = stats['blkio_stats']
       
        memory_usage = memory_stats['usage'] / (1024 ** 2) if 'usage' in memory_stats else 0
        memory_limit = memory_stats['limit'] / (1024 ** 2) if 'limit' in memory_stats else vps['memory'] * 1024
        cpu_usage = (cpu_stats['cpu_usage']['total_usage'] / cpu_stats['system_cpu_usage']) * 100 if cpu_stats.get('system_cpu_usage') else 0
       
        disk_read = sum([s['value'] for s in blkio_stats.get('io_service_bytes_recursive', []) if s['op'] == 'Read']) / (1024 ** 2)
        disk_write = sum([s['value'] for s in blkio_stats.get('io_service_bytes_recursive', []) if s['op'] == 'Write']) / (1024 ** 2)
       
        return jsonify({
            'memory': {
                'used_mb': round(memory_usage, 2),
                'limit_mb': round(memory_limit, 2),
                'percent': round((memory_usage / memory_limit) * 100, 2) if memory_limit else 0
            },
            'cpu': {
                'percent': round(cpu_usage, 2)
            },
            'disk': {
                'read_mb': round(disk_read, 2),
                'write_mb': round(disk_write, 2),
                'total_gb': vps['disk']
            },
            'uptime': stats['read'],
            'configured': {
                'memory': f"{vps['memory']}GB",
                'cpu': f"{vps['cpu']} cores",
                'disk': f"{vps['disk']}GB"
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/vps/<vps_id>/change_password', methods=['POST'])
@login_required
def change_vps_password(vps_id):
    token, vps = db.get_vps_by_id(vps_id)
    if not vps or (vps['created_by'] != current_user.id and not is_admin(current_user)):
        return jsonify({'error': 'VPS not found or access denied'}), 404
   
    try:
        container = docker_client.containers.get(vps['container_id'])
        if container.status != "running":
            return jsonify({'error': 'VPS is not running'}), 400
       
        new_password = generate_ssh_password()
       
        success, stdout, stderr = run_docker_command(
            vps['container_id'],
            ["bash", "-c", f"echo 'root:{new_password}' | chpasswd"]
        )
       
        if not success:
            return jsonify({'error': f'Failed to change password: {stderr}'}), 500
       
        db.update_vps(token, {'password': new_password, 'root_password': new_password})
        logger.info(f"Password changed for VPS {vps_id} by user {current_user.username}")
        return jsonify({'message': 'Password changed successfully', 'password': new_password})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/vps/<vps_id>/upgrade', methods=['POST'])
@login_required
@admin_required
def upgrade_vps(vps_id):
    token, vps = db.get_vps_by_id(vps_id)
    if not vps:
        return jsonify({'error': 'VPS not found'}), 404
   
    try:
        new_memory = int(request.form.get('memory', vps['memory']))
        new_cpu = int(request.form.get('cpu', vps['cpu']))
        new_disk = int(request.form.get('disk', vps['disk']))
       
        if new_memory < 1 or new_memory > 512 or new_cpu < 1 or new_cpu > 32 or new_disk < 10 or new_disk > 1000:
            return jsonify({'error': 'Invalid resource values'}), 400
       
        container = docker_client.containers.get(vps['container_id'])
        if container.status == "running":
            container.stop()
       
        container.update(
            mem_limit=new_memory * 1024 * 1024 * 1024,
            cpu_quota=int(new_cpu * 100000),
            cpu_period=100000
        )
       
        container.start()
       
        db.update_vps(token, {
            'memory': new_memory,
            'cpu': new_cpu,
            'disk': new_disk,
            'status': 'running'
        })
       
        logger.info(f"VPS {vps_id} upgraded by admin {current_user.username}")
        return jsonify({'message': 'VPS resources upgraded successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/vps/<vps_id>/logs')
@login_required
def vps_logs(vps_id):
    token, vps = db.get_vps_by_id(vps_id)
    if not vps or (vps['created_by'] != current_user.id and not is_admin(current_user)):
        return jsonify({'error': 'VPS not found or access denied'}), 404
   
    try:
        container = docker_client.containers.get(vps['container_id'])
        logs = container.logs(tail=2000, timestamps=True).decode('utf-8')
        return jsonify({'logs': logs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/vps/<vps_id>/backup')
@login_required
@admin_required
def backup_vps(vps_id):
    token, vps = db.get_vps_by_id(vps_id)
    if not vps:
        return jsonify({'error': 'VPS not found'}), 404
   
    try:
        container = docker_client.containers.get(vps['container_id'])
        was_running = container.status == "running"
        if was_running:
            container.stop()
       
        backup_image_tag = f"hvm/{vps['vps_id'].lower()}:backup_{int(time.time())}"
        container.commit(repository=backup_image_tag.split(':')[0], tag=backup_image_tag.split(':')[1])
       
        if was_running:
            container.start()
       
        image = docker_client.images.get(backup_image_tag)
        backup_file = f"{vps['vps_id']}_backup_{int(time.time())}.tar"
        with open(backup_file, 'wb') as f:
            for chunk in image.save(named=True):
                f.write(chunk)
       
        logger.info(f"Backup created for VPS {vps_id} by admin {current_user.username}")
        return send_file(backup_file, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if os.path.exists(backup_file):
            os.remove(backup_file)
@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    update_system_stats()
    all_vps = db.get_all_vps()
    all_users = db.get_all_users()
    banned_users = db.get_banned_users()
   
    panel_name = db.get_setting('panel_name', PANEL_NAME)
    watermark = db.get_setting('watermark', WATERMARK)
    welcome_message = db.get_setting('welcome_message', WELCOME_MESSAGE)
    server_ip = db.get_setting('server_ip', SERVER_IP)
    max_containers = db.get_setting('max_containers', MAX_CONTAINERS)
    max_vps_per_user = db.get_setting('max_vps_per_user', MAX_VPS_PER_USER)
   
    total_vps = len(all_vps)
    total_users = len(all_users)
    total_banned = len(banned_users)
    total_restarts = db.get_stat('total_restarts')
    total_vps_created = db.get_stat('total_vps_created')
   
    try:
        with open('hvm_panel.log', 'r') as f:
            recent_logs = ''.join(f.readlines()[-200:])
    except:
        recent_logs = 'No logs available'
   
    return render_template('admin.html',
                         system_stats=system_stats,
                         vps_list=list(all_vps.values()),
                         vps_stats=vps_stats_cache,
                         users=all_users,
                         banned_users=banned_users,
                         panel_name=panel_name,
                         watermark=watermark,
                         welcome_message=welcome_message,
                         server_ip=server_ip,
                         max_containers=max_containers,
                         max_vps_per_user=max_vps_per_user,
                         total_vps=total_vps,
                         total_users=total_users,
                         total_banned=total_banned,
                         total_restarts=total_restarts,
                         total_vps_created=total_vps_created,
                         recent_logs=recent_logs)
@app.route('/admin/settings', methods=['POST'])
@login_required
@admin_required
def admin_settings():
    panel_name = request.form.get('panel_name')
    watermark = request.form.get('watermark')
    welcome_message = request.form.get('welcome_message')
    server_ip = request.form.get('server_ip')
    max_containers = request.form.get('max_containers')
    max_vps_per_user = request.form.get('max_vps_per_user')
   
    if panel_name:
        db.set_setting('panel_name', panel_name)
    if watermark:
        db.set_setting('watermark', watermark)
    if welcome_message:
        db.set_setting('welcome_message', welcome_message)
    if server_ip:
        db.set_setting('server_ip', server_ip)
    if max_containers and max_containers.isdigit():
        db.set_setting('max_containers', int(max_containers))
    if max_vps_per_user and max_vps_per_user.isdigit():
        db.set_setting('max_vps_per_user', int(max_vps_per_user))
   
    logger.info(f"Settings updated by admin {current_user.username}")
    return redirect(url_for('admin_panel'))
@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'user')
       
        if not username or not password:
            return render_template('add_user.html', error='All fields required', panel_name=PANEL_NAME)
       
        if len(password) < 12:
            return render_template('add_user.html', error='Password must be at least 12 characters', panel_name=PANEL_NAME)
       
        if db.create_user(username, password, role):
            logger.info(f"New user {username} added by admin {current_user.username}")
            return redirect(url_for('admin_panel'))
        else:
            return render_template('add_user.html', error='Username exists', panel_name=PANEL_NAME)
   
    return render_template('add_user.html', panel_name=PANEL_NAME)
@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = db.get_user_by_id(user_id)
    if not user:
        return render_template('error.html', error='User not found', panel_name=PANEL_NAME)
   
    if request.method == 'POST':
        username = request.form.get('username', user['username'])
        password = request.form.get('password')
        role = request.form.get('role', user['role'])
       
        if password and len(password) < 12:
            return render_template('edit_user.html', error='Password must be at least 12 characters if changed', user=user, panel_name=PANEL_NAME)
       
        success = db.update_user(user_id, username, password, role)
        if success:
            logger.info(f"User {user_id} edited by admin {current_user.username}")
            return redirect(url_for('admin_panel'))
        else:
            return render_template('edit_user.html', error='Update failed, perhaps username exists', user=user, panel_name=PANEL_NAME)
   
    return render_template('edit_user.html', user=user, panel_name=PANEL_NAME)
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if db.delete_user(user_id):
        logger.info(f"User {user_id} deleted by admin {current_user.username}")
        return jsonify({'message': 'User deleted successfully'})
    return jsonify({'error': 'Failed to delete user'}), 500
@app.route('/admin/user/<user_id>/ban')
@login_required
@admin_required
def ban_user(user_id):
    db.ban_user(int(user_id))
    logger.info(f"User {user_id} banned by admin {current_user.username}")
    return redirect(url_for('admin_panel'))
@app.route('/admin/user/<user_id>/unban')
@login_required
@admin_required
def unban_user(user_id):
    db.unban_user(int(user_id))
    logger.info(f"User {user_id} unbanned by admin {current_user.username}")
    return redirect(url_for('admin_panel'))
@app.route('/admin/user/<user_id>/make_admin')
@login_required
@admin_required
def make_admin(user_id):
    db.update_user_role(int(user_id), 'admin')
    logger.info(f"User {user_id} made admin by {current_user.username}")
    return redirect(url_for('admin_panel'))
@app.route('/admin/user/<user_id>/remove_admin')
@login_required
@admin_required
def remove_admin(user_id):
    db.update_user_role(int(user_id), 'user')
    logger.info(f"User {user_id} admin role removed by {current_user.username}")
    return redirect(url_for('admin_panel'))
@app.route('/admin/vps/<vps_id>/suspend')
@login_required
@admin_required
def suspend_vps(vps_id):
    token, vps = db.get_vps_by_id(vps_id)
    if not vps:
        return jsonify({'error': 'VPS not found'}), 404
   
    try:
        container = docker_client.containers.get(vps['container_id'])
        container.stop()
    except:
        pass
   
    db.update_vps(token, {'status': 'suspended'})
    logger.info(f"VPS {vps_id} suspended by admin {current_user.username}")
    return redirect(url_for('admin_panel'))
@app.route('/admin/vps/<vps_id>/unsuspend')
@login_required
@admin_required
def unsuspend_vps(vps_id):
    token, vps = db.get_vps_by_id(vps_id)
    if not vps:
        return jsonify({'error': 'VPS not found'}), 404
   
    try:
        container = docker_client.containers.get(vps['container_id'])
        container.start()
    except:
        pass
   
    db.update_vps(token, {'status': 'running'})
    logger.info(f"VPS {vps_id} unsuspended by admin {current_user.username}")
    return redirect(url_for('admin_panel'))
@app.route('/admin/backup')
@login_required
@admin_required
def admin_backup():
    if db.backup_data():
        logger.info(f"System backup created by admin {current_user.username}")
        return send_file(BACKUP_FILE, as_attachment=True)
    return jsonify({'error': 'Backup failed'}), 500
@app.route('/admin/restore', methods=['POST'])
@login_required
@admin_required
def admin_restore():
    if 'backup_file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
   
    file = request.files['backup_file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
   
    if file and file.filename.endswith('.json'):
        file.save(BACKUP_FILE)
        if db.restore_data():
            logger.info(f"System restore performed by admin {current_user.username}")
            return jsonify({'message': 'Restore completed successfully'})
   
    return jsonify({'error': 'Restore failed'}), 500
@app.route('/admin/docker_prune')
@login_required
@admin_required
def admin_docker_prune():
    try:
        # Only prune unused resources
        pruned = docker_client.prune_containers()
        docker_client.prune_images(filters={'dangling': True})
        docker_client.prune_volumes()
        logger.info(f"Docker prune performed by admin {current_user.username}")
        return jsonify({'message': 'Pruned unused resources', 'pruned': pruned})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
# WebSocket for console
@socketio.on('connect', namespace='/console')
def handle_console_connect():
    logger.info('Client connected to console')
@socketio.on('disconnect', namespace='/console')
def handle_console_disconnect():
    sid = request.sid
    if sid in console_sessions:
        os.killpg(os.getpgid(console_sessions[sid]['pid']), signal.SIGTERM)
        del console_sessions[sid]
    logger.info('Client disconnected from console')
@socketio.on('start_shell', namespace='/console')
def start_shell(data):
    vps_id = data.get('vps_id')
    if not vps_id:
        emit('error', 'Missing vps_id')
        return
   
    token, vps = db.get_vps_by_id(vps_id)
    if not vps or (vps['created_by'] != current_user.id and not is_admin(current_user)):
        emit('error', 'Access denied')
        return
   
    try:
        container = docker_client.containers.get(vps['container_id'])
        if container.status != 'running':
            emit('error', 'VPS not running')
            return
    except:
        emit('error', 'Container not found')
        return
   
    master_fd, slave_fd = pty.openpty()
    fcntl.fcntl(master_fd, fcntl.F_SETFL, fcntl.fcntl(master_fd, fcntl.F_GETFL) | os.O_NONBLOCK)
   
    cmd = ['docker', 'exec', '-it', vps['container_id'], '/bin/bash']
    pid = os.fork()
    if pid == 0:
        os.setsid()
        os.dup2(slave_fd, 0)
        os.dup2(slave_fd, 1)
        os.dup2(slave_fd, 2)
        os.close(master_fd)
        os.execvp(cmd[0], cmd)
    else:
        os.close(slave_fd)
        sid = request.sid
        console_sessions[sid] = {'fd': master_fd, 'pid': pid}
       
        def reader():
            while True:
                try:
                    ready = select.select([master_fd], [], [], 1)[0]
                    if ready:
                        data = os.read(master_fd, 1024)
                        if not data:
                            break
                        emit('output', data.decode('utf-8', errors='ignore'), namespace='/console')
                except:
                    break
            if sid in console_sessions:
                del console_sessions[sid]
            socketio.emit('shell_exit', namespace='/console', to=sid)
       
        threading.Thread(target=reader, daemon=True).start()
@socketio.on('input', namespace='/console')
def handle_input(data):
    sid = request.sid
    if sid in console_sessions:
        try:
            os.write(console_sessions[sid]['fd'], data.encode('utf-8'))
        except:
            pass
@socketio.on('resize', namespace='/console')
def handle_resize(data):
    sid = request.sid
    if sid in console_sessions:
        fd = console_sessions[sid]['fd']
        try:
            winsize = struct.pack("HHHH", data['rows'], data['cols'], 0, 0)
            fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
        except:
            pass
# SocketIO for admin radar (real-time monitoring)
@socketio.on('connect', namespace='/admin')
def handle_admin_connect():
    logger.info('Admin connected to radar')
    emit('system_stats', system_stats)
    emit('vps_stats', vps_stats_cache)
@socketio.on('disconnect', namespace='/admin')
def handle_admin_disconnect():
    logger.info('Admin disconnected from radar')
@login_manager.user_loader
def load_user(user_id):
    user_data = db.get_user_by_id(int(user_id))
    if user_data:
        return User(user_data['id'], user_data['username'], user_data['role'])
    return None
def system_stats_updater():
    while True:
        update_system_stats()
        socketio.emit('system_stats', system_stats, namespace='/admin')
        time.sleep(10)
def vps_stats_updater():
    while True:
        update_vps_stats()
        socketio.emit('vps_stats', vps_stats_cache, namespace='/admin')
        time.sleep(30)
def anti_miner_monitor():
    while True:
        try:
            for token, vps in db.get_all_vps().items():
                if vps['status'] != 'running':
                    continue
               
                try:
                    container = docker_client.containers.get(vps['container_id'])
                    if container.status != 'running':
                        continue
                   
                    stats = container.stats(stream=False)
                    cpu_usage = (stats['cpu_stats']['cpu_usage']['total_usage'] / stats['cpu_stats']['system_cpu_usage']) * 100 if stats['cpu_stats'].get('system_cpu_usage') else 0
                   
                    if cpu_usage > 95:
                        logger.warning(f"High CPU usage detected in VPS {vps['vps_id']}, suspending...")
                        container.stop()
                        db.update_vps(token, {'status': 'suspended'})
                        continue
                   
                    success, stdout, stderr = run_docker_command(vps['container_id'], ["ps", "aux"])
                    if not success:
                        continue
                   
                    output = stdout.lower()
                    for pattern in MINER_PATTERNS:
                        if pattern in output:
                            logger.warning(f"Mining detected in VPS {vps['vps_id']}, suspending...")
                            container.stop()
                            db.update_vps(token, {'status': 'suspended'})
                            break
                except:
                    continue
        except Exception as e:
            logger.error(f"Error in anti-miner monitor: {e}")
        time.sleep(120)
def clean_stopped_containers():
    while True:
        try:
            stopped_containers = docker_client.containers.list(filters={"status": "exited"})
            for cont in stopped_containers:
                if not any(vps['container_id'] == cont.id for vps in db.get_all_vps().values()):
                    cont.remove()
        except Exception as e:
            logger.error(f"Error cleaning stopped containers: {e}")
        time.sleep(600)

def check_expired_vps():
    """Background task to check and remove expired VPS instances"""
    while True:
        try:
            now = datetime.datetime.now()
            all_vps = db.get_all_vps()
            
            for vps_id, vps_data in all_vps.items():
                if vps_data.get('expires_at'):
                    expires_at = datetime.datetime.fromisoformat(vps_data['expires_at'])
                    if now > expires_at and vps_data.get('status') != 'expired':
                        # Mark VPS as expired and stop container
                        try:
                            container = docker_client.containers.get(vps_data['container_id'])
                            container.stop()
                            container.remove()
                            
                            # Update VPS status in database
                            vps_data['status'] = 'expired'
                            db.update_vps(vps_id, vps_data)
                            logger.info(f"VPS {vps_id} has been expired and removed")
                        except Exception as e:
                            logger.error(f"Failed to remove expired VPS {vps_id}: {str(e)}")
            
            time.sleep(60)  # Check every minute
        except Exception as e:
            logger.error(f"Error in expired VPS check: {str(e)}")
            time.sleep(300)  # Wait 5 minutes if there's an error

# Start the background thread when the app starts
def start_background_tasks():
    expiration_thread = threading.Thread(target=check_expired_vps, daemon=True)
    expiration_thread.start()

def monitor_containers():
    while True:
        try:
            for token, vps in db.get_all_vps().items():
                try:
                    cont = docker_client.containers.get(vps['container_id'])
                    status = cont.status
                    if datetime.datetime.now() > datetime.datetime.strptime(vps['expires_at'], '%Y-%m-%d %H:%M:%S.%f') and status == 'running':
                        cont.stop()
                        db.update_vps(token, {'status': 'expired'})
                        socketio.emit('vps_status', {'vps_id': vps['vps_id'], 'status': 'expired'})
                        continue
                    if status != vps['status']:
                        db.update_vps(token, {'status': status})
                        socketio.emit('vps_status', {'vps_id': vps['vps_id'], 'status': status})
                except docker.errors.NotFound:
                    if vps['status'] != 'not_found':
                        db.update_vps(token, {'status': 'not_found'})
                        socketio.emit('vps_status', {'vps_id': vps['vps_id'], 'status': 'not_found'})
                except Exception as e:
                    logger.error(f"Error monitoring container {vps['container_id']}: {e}")
        except Exception as e:
            logger.error(f"Error in container monitor: {e}")
        time.sleep(15)
if __name__ == '__main__':
    os.makedirs("image_cache", exist_ok=True)
   
    stats_thread = threading.Thread(target=system_stats_updater, daemon=True)
    stats_thread.start()
   
    vps_stats_thread = threading.Thread(target=vps_stats_updater, daemon=True)
    vps_stats_thread.start()
   
    miner_thread = threading.Thread(target=anti_miner_monitor, daemon=True)
    miner_thread.start()
   
    clean_thread = threading.Thread(target=clean_stopped_containers, daemon=True)
    clean_thread.start()
   
    monitor_thread = threading.Thread(target=monitor_containers, daemon=True)
    monitor_thread.start()
   
    socketio.run(app, host='0.0.0.0', port=SERVER_PORT, debug=DEBUG, allow_unsafe_werkzeug=True)