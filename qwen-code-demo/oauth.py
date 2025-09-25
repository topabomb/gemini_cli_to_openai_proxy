"""
Qwen OAuth2 设备授权流程演示
本脚本演示完整的 OAuth2 设备授权流程，并将凭据保存到 JSON 文件。
"""
import json
import webbrowser
import os
import datetime
from .oauth2_client import QwenOAuth2Client


def main():
    print("启动 Qwen OAuth2 设备授权演示...")
    print("=" * 50)

    # 创建 OAuth2 客户端
    client = QwenOAuth2Client()

    try:
        # 第 1 步：申请设备授权
        print("第 1 步：请求设备授权...")
        device_response = client.request_device_authorization()
        
        device_code = device_response.get('device_code')
        user_code = device_response.get('user_code')
        verification_uri = device_response.get('verification_uri')
        verification_uri_complete = device_response.get('verification_uri_complete', verification_uri)
        
        if not device_code:
            raise Exception("响应中缺少 device_code")
        if not user_code:
            raise Exception("响应中缺少 user_code")
        if not verification_uri:
            raise Exception("响应中缺少 verification_uri")
        
        # 确保 verification_uri_complete 可用
        if not verification_uri_complete:
            verification_uri_complete = verification_uri
        
        print(f"用户代码：{user_code}")
        print(f"授权地址：{verification_uri}")
        print(f"完整地址：{verification_uri_complete}")
        
        # 打开浏览器执行授权
        print("\n正在打开浏览器进行认证...")
        webbrowser.open(verification_uri_complete)
        
        print(f"\n请访问上述地址并输入用户代码：{user_code}")
        print("等待用户完成授权...")
        
        # 第 2 步：轮询令牌
        print("\n第 2 步：轮询访问令牌...")
        token_response = client.poll_for_token(device_code)
        
        print("授权成功！")
        print(f"已获取访问令牌：{token_response.get('access_token', '')[:20]}...")
        
        # 第 3 步：保存凭据到文件
        print("\n第 3 步：保存凭据到文件...")
        credentials = client.get_credentials()
        
        # 如无则创建 demo 目录
        os.makedirs('demo', exist_ok=True)
        
        # 保存到 JSON 文件
        with open('demo/oauth_creds.json', 'w', encoding='utf-8') as f:
            json.dump(credentials, f, indent=2, ensure_ascii=False)
        
        print("凭据已保存到 demo/oauth_creds.json")
        print("\n完整凭据：")
        print(json.dumps(credentials, indent=2, ensure_ascii=False))
        
        # 第 4 步：校验令牌有效期
        print(f"\n第 4 步：校验令牌有效性...")
        is_valid = client.is_token_valid()
        print(f"令牌是否有效：{is_valid}")
        
        if is_valid:
            expiry_time = credentials['expiry_date'] / 1000  # 毫秒转秒
            expiry_datetime = datetime.datetime.fromtimestamp(expiry_time)
            print(f"令牌过期时间：{expiry_datetime}")
        else:
            print("令牌已过期或无效")
            
    except Exception as e:
        print(f"OAuth2 流程出错：{str(e)}")
        return 1
    
    print("\n" + "=" * 50)
    print("OAuth2 设备授权演示完成！")
    return 0


if __name__ == "__main__":
    exit(main())