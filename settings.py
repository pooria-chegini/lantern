import os
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
MAX_HOSTS = 1024
WORKERS = 20
# حداقل نسخه امن هر پلتفرم (دستی تنظیم کنید، مثال: '15.2(7)E9'). خالی = N/A
MIN_VERSIONS = {}
KEEP_SNAPSHOTS = 60   # تعداد snapshot نگه‌داری‌شده برای هر سوئیچ
APP_NAME = 'LANtern'
GITHUB_URL = os.environ.get('LANTERN_GITHUB', 'https://github.com/<your-user>/lantern')
