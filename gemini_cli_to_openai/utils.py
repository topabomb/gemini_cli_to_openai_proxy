"""
通用工具函数迁移自 src/utils.py。
"""
import platform


CLI_VERSION = "0.1.5"


def get_user_agent():
    """生成与 gemini-cli 一致的 User-Agent。"""
    version = CLI_VERSION
    system = platform.system()
    arch = platform.machine()
    return f"GeminiCLI/{version} ({system}; {arch})"


def get_platform_string():
    """生成平台标识字符串（与 gemini-cli 一致）。"""
    system = platform.system().upper()
    arch = platform.machine().upper()

    if system == "DARWIN":
        if arch in ["ARM64", "AARCH64"]:
            return "DARWIN_ARM64"
        else:
            return "DARWIN_AMD64"
    elif system == "LINUX":
        if arch in ["ARM64", "AARCH64"]:
            return "LINUX_ARM64"
        else:
            return "LINUX_AMD64"
    elif system == "WINDOWS":
        return "WINDOWS_AMD64"
    else:
        return "PLATFORM_UNSPECIFIED"


def get_client_metadata(project_id=None):
    """构建客户端元数据。"""
    return {
        "ideType": "IDE_UNSPECIFIED",
        "platform": get_platform_string(),
        "pluginType": "GEMINI",
        "duetProject": project_id,
    }


