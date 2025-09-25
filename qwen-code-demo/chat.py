"""
Qwen LLM 聊天模块
实现与 Qwen LLM 的流式与非流式交互
"""
import argparse
import json
import os
import sys
import httpx
import time
from typing import Optional
from .config import USER_AGENT
from .oauth2_client import QwenOAuth2Client


def get_available_models_from_api(access_token, resource_url=None):
    """
    从 API 获取可用模型列表（优先使用）
    
    参数:
        access_token (str): 认证所需的访问令牌
        resource_url (str): 凭据中的资源 URL（如果可用）
    
    返回:
        list | None: 模型 ID 列表，失败时返回 None
    """
    # 与 QwenContentGenerator.getCurrentEndpoint() 的规则一致
    if resource_url:
        base_endpoint = resource_url
        suffix = '/v1'
        # 规范化 URL：无协议则补 https://，无 /v1 则补 /v1
        if base_endpoint.startswith('http'):
            normalized_url = base_endpoint
        else:
            normalized_url = f"https://{base_endpoint}"
        if normalized_url.endswith(suffix):
            api_url = f"{normalized_url}/models"
        else:
            api_url = f"{normalized_url}{suffix}/models"
    else:
        # 使用 DashScope 兼容端点作为默认
        api_url = "https://dashscope.aliyuncs.com/compatible-mode/v1/models"
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT
    }
    
    try:
        response = httpx.get(api_url, headers=headers, timeout=60)
        if response.status_code != 200:
            print(f"从 API 获取模型列表失败，状态码: {response.status_code}")
            print(f"请求的 API URL: {api_url}")
            return None
        
        response_data = response.json()
        if 'data' in response_data and isinstance(response_data['data'], list):
            models = [model.get('id') for model in response_data['data'] if 'id' in model]
            return models
        elif 'model_list' in response_data and isinstance(response_data['model_list'], list):
            models = [model.get('model') for model in response_data['model_list'] if 'model' in model]
            return models
        else:
            print("获取模型列表的响应格式异常")
            print(f"响应内容: {response_data}")
            return None
    except httpx.RequestError as e:
        print(f"请求错误（获取模型列表）: {e}")
        return None
    except json.JSONDecodeError:
        print("解析模型列表响应 JSON 失败")
        return None


def get_available_models_hardcoded():
    """
    返回基于代码与经验整理的已知模型列表（作为降级方案）
    """
    return [
        "qwen3-coder-plus",      # 编码任务主力模型
        "qwen3-coder-flash",     # 更快、更经济的编码模型
        "coder-model",           # 通用编码模型
        "vision-model"           # 通用视觉模型
    ]


def get_available_models(access_token, resource_url=None):
    """
    获取可用模型列表，优先调用 API，失败则回退到本地已知列表
    """
    models = get_available_models_from_api(access_token, resource_url)
    if models is None:
        print("API 模型列表不可用，使用本地已知模型列表")
        models = get_available_models_hardcoded()
    return models


def call_qwen_api_streaming(prompt, access_token, resource_url=None, model="qwen3-coder-plus"):
    """
    以流式方式调用 Qwen API
    
    返回:
        generator: 逐块返回的模型输出
    """
    if resource_url:
        if not resource_url.startswith('http'):
            resource_url = f"https://{resource_url}"
        if not resource_url.endswith('/v1'):
            resource_url += '/v1'
        api_url = f"{resource_url}/chat/completions"
    else:
        api_url = "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
    
    payload = {
        "model": model,
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "stream": True
    }
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT
    }
    
    with httpx.stream("POST", api_url, json=payload, headers=headers, timeout=60) as response:
        if response.status_code != 200:
            print(f"API 请求失败，状态码: {response.status_code}")
            print(f"响应内容: {response.text}")
            return
        for chunk in response.iter_lines():
            if chunk:
                if chunk.startswith("data: "):
                    chunk = chunk[6:]
                if chunk.strip() == "[DONE]":
                    break
                try:
                    data = json.loads(chunk)
                    if 'choices' in data and len(data['choices']) > 0:
                        delta = data['choices'][0].get('delta', {})
                        content = delta.get('content', '')
                        if content:
                            yield content
                except json.JSONDecodeError:
                    continue


def call_qwen_api_non_streaming(prompt, access_token, resource_url=None, model="qwen3-coder-plus"):
    """
    以非流式方式调用 Qwen API
    
    返回:
        str | None: 完整响应文本
    """
    if resource_url:
        if not resource_url.startswith('http'):
            resource_url = f"https://{resource_url}"
        if not resource_url.endswith('/v1'):
            resource_url += '/v1'
        api_url = f"{resource_url}/chat/completions"
    else:
        api_url = "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
    
    payload = {
        "model": model,
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "stream": False
    }
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT
    }
    try:
        response = httpx.post(api_url, json=payload, headers=headers, timeout=60)
        if response.status_code != 200:
            print(f"API 请求失败，状态码: {response.status_code}")
            print(f"响应内容: {response.text}")
            return None
        response_data = response.json()
        if 'choices' in response_data and len(response_data['choices']) > 0:
            return response_data['choices'][0]['message']['content']
        else:
            print("API 响应中未找到内容")
            return None
    except httpx.RequestError as e:
        print(f"请求错误: {e}")
        return None
    except json.JSONDecodeError:
        print("解析 JSON 响应失败")
        return None


def call_qwen_api(prompt, access_token, resource_url=None, model="qwen3-coder-plus", stream=False):
    """
    调用 Qwen API（自动选择流式/非流式）
    """
    if stream:
        return call_qwen_api_streaming(prompt, access_token, resource_url, model)
    else:
        return call_qwen_api_non_streaming(prompt, access_token, resource_url, model)


def _is_token_valid(expiry_date_ms: Optional[int], access_token: Optional[str]) -> bool:
    """
    本地校验令牌是否有效（含 30 秒缓冲）
    """
    if not expiry_date_ms or not access_token:
        return False
    now = int(time.time() * 1000)
    return now < (expiry_date_ms - 30000)


def _load_credentials_from_file(path: str = 'demo/oauth_creds.json'):
    """
    从文件读取凭据（若不存在或格式错误则返回 None）
    """
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        return None


def _save_credentials_to_file(creds: dict, path: str = 'demo/oauth_creds.json'):
    """
    将凭据写回文件
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(creds, f, indent=2, ensure_ascii=False)


def _ensure_valid_credentials(credentials: dict) -> Optional[dict]:
    """
    确保凭据有效：
    - 若即将过期且存在 refresh_token，则尝试刷新并回写文件
    - 成功则返回最新凭据，失败返回 None
    """
    access_token = credentials.get('access_token')
    refresh_token = credentials.get('refresh_token')
    expiry_date = credentials.get('expiry_date')
    resource_url = credentials.get('resource_url')

    if _is_token_valid(expiry_date, access_token):
        return credentials

    if not refresh_token:
        print("提示：凭据已过期且无刷新令牌，请先运行 'python -m demo.oauth' 完成授权。")
        return None

    # 使用 OAuth 客户端执行刷新
    client = QwenOAuth2Client()
    try:
        token_data = client.refresh_access_token(refresh_token)
    except Exception as e:
        print(f"刷新访问令牌失败：{e}")
        return None

    # 将新令牌合并到原有结构并回写
    new_creds = {
        'access_token': token_data.get('access_token'),
        'refresh_token': token_data.get('refresh_token', refresh_token),
        'token_type': token_data.get('token_type'),
        'expiry_date': int(time.time() * 1000) + token_data.get('expires_in', 3600) * 1000,
        'resource_url': token_data.get('resource_url', resource_url),
    }
    _save_credentials_to_file(new_creds)
    return new_creds


def chat_with_qwen(prompt, stream=False, model="qwen3-coder-plus"):
    """
    与 Qwen 进行对话（主入口）
    """
    credentials = _load_credentials_from_file('demo/oauth_creds.json')
    if credentials is None:
        print("错误：未找到凭据文件或格式不正确。请先运行 'python -m demo.oauth'。")
        return False

    # 确保令牌有效（必要时自动刷新）
    updated = _ensure_valid_credentials(credentials)
    if updated is None:
        return False

    access_token = updated.get('access_token')
    resource_url = updated.get('resource_url')
    if not access_token:
        print("错误：凭据中未包含有效的 access_token。")
        return False

    response = call_qwen_api(prompt, access_token, resource_url, stream=stream, model=model)
    if stream:
        if response is None or not hasattr(response, '__iter__'):
            print("调用 Qwen API 失败（流式）")
            return False
        print("Qwen: ", end='', flush=True)
        try:
            for content in response:
                print(content, end='', flush=True)
            print()
        except TypeError:
            print("调用 Qwen API 失败（流式）")
            return False
        return True
    else:
        if response is None:
            print("调用 Qwen API 失败（非流式）")
            return False
        elif isinstance(response, str):
            print(f"Qwen: {response}")
            return True
        elif hasattr(response, '__iter__') and not isinstance(response, (str, bytes)):
            try:
                full_response = ''.join(response)
                print(f"Qwen: {full_response}")
                return True
            except TypeError:
                print("调用 Qwen API 失败（非流式-迭代器）")
                return False
        else:
            print("调用 Qwen API 失败（未知返回类型）")
            return False


def list_models():
    """
    列出可用模型
    """
    credentials = _load_credentials_from_file('demo/oauth_creds.json')
    if credentials is None:
        print("错误：未找到凭据文件或格式不正确。请先运行 'python -m demo.oauth'。")
        return False

    # 确保令牌有效（必要时自动刷新）
    updated = _ensure_valid_credentials(credentials)
    if updated is None:
        return False

    access_token = updated.get('access_token')
    resource_url = updated.get('resource_url')
    if not access_token:
        print("错误：凭据中未包含有效的 access_token。")
        return False

    models = get_available_models(access_token, resource_url)
    if models is not None:
        if len(models) > 0:
            print("可用模型：")
            for model in models:
                print(f"  - {model}")
            return True
        else:
            print("响应中未找到模型")
            return False
    else:
        print("从 API 获取模型列表失败")
        return False


def main():
    parser = argparse.ArgumentParser(description='与 Qwen LLM 进行聊天')
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # chat 子命令
    chat_parser = subparsers.add_parser('chat', help='向 Qwen 发送提示词')
    chat_parser.add_argument('-p', '--prompt', type=str, required=True, help='要发送给 Qwen 的提示词')
    chat_parser.add_argument('-s', '--stream', action='store_true', help='启用流式响应')
    chat_parser.add_argument('-m', '--model', type=str, default="qwen3-coder-plus", help='使用的模型（默认：qwen3-coder-plus）')
    
    # list-models 子命令
    subparsers.add_parser('list-models', help='列出可用模型')
    
    args = parser.parse_args()
    
    if args.command == 'list-models':
        success = list_models()
        if not success:
            sys.exit(1)
    elif args.command == 'chat':
        if args.prompt:
            success = chat_with_qwen(args.prompt, stream=args.stream, model=args.model)
            if not success:
                sys.exit(1)
        else:
            print("错误：chat 命令需要提供 -p/--prompt 参数")
            chat_parser.print_help()
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()