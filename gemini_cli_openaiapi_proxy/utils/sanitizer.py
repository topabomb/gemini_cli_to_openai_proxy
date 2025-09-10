"""
通用脱敏工具模块。
"""
from typing import Optional
MAX_EMAIL_LENGTH = 12
def sanitize_email(email: Optional[str]) -> str:
    """
    对电子邮件地址进行脱敏处理。
    规则：保留@前第一个字符，第二个用*替代，以此类推。
          处理后长度不足12位则用*填充至12位，超过12位则截断。
    """
    if not email or "@" not in email:
        return str(email)
        
    local_part, domain = email.split('@', 1)
    
    sanitized_local = []
    for i, char in enumerate(local_part):
        sanitized_local.append(char if i % 2 == 0 else '*')
    
    sanitized_str = "".join(sanitized_local)
    
    if len(sanitized_str) < MAX_EMAIL_LENGTH:
        sanitized_str = sanitized_str.ljust(MAX_EMAIL_LENGTH, '*')
    elif len(sanitized_str) > MAX_EMAIL_LENGTH:
        sanitized_str = sanitized_str[:MAX_EMAIL_LENGTH]
        
    return f"{sanitized_str}@{domain}"

def sanitize_project_id(pid: Optional[str]) -> str:
    """
    对项目ID进行脱敏处理。
    规则：只保留最后4位，前面用***-拼接。
    """
    if not pid:
        return str(pid)
    if len(pid) <= 4:
        return "***"
    return f"***-{pid[-4:]}"
