"""
OAUTH2 Configuration for Qwen API
"""
import os

# Qwen OAuth Configuration
QWEN_OAUTH_BASE_URL = 'https://chat.qwen.ai'
QWEN_OAUTH_DEVICE_CODE_ENDPOINT = f'{QWEN_OAUTH_BASE_URL}/api/v1/oauth2/device/code'
QWEN_OAUTH_TOKEN_ENDPOINT = f'{QWEN_OAUTH_BASE_URL}/api/v1/oauth2/token'

# OAuth Client Configuration
QWEN_OAUTH_CLIENT_ID = 'f0304373b74a44d2b584a3fb70ca9e56'

# OAuth Scope
QWEN_OAUTH_SCOPE = 'openid profile email model.completion'
QWEN_OAUTH_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code'

# Token refresh buffer (30 seconds)
TOKEN_REFRESH_BUFFER_MS = 30 * 1000

# Polling configuration
POLL_INTERVAL = 2  # seconds
MAX_POLL_ATTEMPTS = 900 # 30 minutes (900 * 2 seconds)

# User-Agent Configuration
import platform

CLI_VERSION = os.environ.get('CLI_VERSION', '1.0.0')
USER_AGENT = f'QwenCode/{CLI_VERSION} ({platform.system()}; {platform.machine()})'
