"""
Model Validator
Validates all known Qwen models by sending a simple test request to each
"""
import httpx
import json
from .config import USER_AGENT


def validate_model(model_name, access_token, resource_url=None):
    """
    Validate a single model by sending a test request
    
    Args:
        model_name (str): The model to validate
        access_token (str): The access token for authentication
        resource_url (str): The resource URL from credentials, if available
    
    Returns:
        bool: True if the model is valid, False otherwise
    """
    # Use the resource URL from credentials if available, otherwise use default
    if resource_url:
        # Ensure the URL is properly formatted
        if not resource_url.startswith('http'):
            resource_url = f"https://{resource_url}"
        if not resource_url.endswith('/v1'):
            resource_url += '/v1'
        api_url = f"{resource_url}/chat/completions"
    else:
        # Default to DashScope compatible endpoint
        api_url = "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
    
    # Prepare the request payload - a simple test request
    payload = {
        "model": model_name,
        "messages": [
            {
                "role": "user",
                "content": "Hello, just testing if this model is available. Please respond with a short 'available' message if you can."
            }
        ],
        "stream": False # Non-streaming request for easier validation
    }
    
    # Prepare headers
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT
    }
    
    try:
        # Make the API request
        response = httpx.post(
            api_url,
            json=payload,
            headers=headers,
            timeout=30  # 30 seconds timeout
        )
        
        # Check if the request was successful
        if response.status_code == 200:
            # Try to parse the response to ensure it's valid
            response_data = response.json()
            if 'choices' in response_data and len(response_data['choices']) > 0:
                return True
            else:
                print(f"  Model {model_name}: Response format invalid")
                return False
        elif response.status_code == 400 or response.status_code == 404:
            # Parse error response to see if it's a model not found error
            try:
                error_data = response.json()
                if 'error' in error_data:
                    error_msg = error_data['error'].get('message', '').lower()
                    if 'model' in error_msg and ('not supported' in error_msg or 'not found' in error_msg):
                        print(f"  Model {model_name}: Not available - {error_data['error'].get('message', 'Unknown error')}")
                        return False
            except:
                pass
            print(f"  Model {model_name}: Request failed with status {response.status_code}")
            return False
        else:
            print(f"  Model {model_name}: Request failed with status {response.status_code}")
            return False
            
    except httpx.RequestError as e:
        print(f"  Model {model_name}: Request error - {e}")
        return False
    except json.JSONDecodeError:
        print(f" Model {model_name}: Failed to parse JSON response")
        return False


def validate_all_models():
    """Validate all known models"""
    # Load credentials
    try:
        with open('demo/oauth_creds.json', 'r', encoding='utf-8') as f:
            credentials = json.load(f)
    except FileNotFoundError:
        print("Error: Credentials file not found. Please run 'python -m demo.oauth' first.")
        return False
    except json.JSONDecodeError:
        print("Error: Invalid credentials file format.")
        return False
    
    # Check if the token is still valid, otherwise refresh it
    access_token = credentials.get('access_token')
    resource_url = credentials.get('resource_url')
    if not access_token:
        print("Error: No access token found in credentials.")
        return False
    
    # List of known models to validate
    models_to_test = [
        "qwen3-coder-plus",      # Main model for coding tasks
        "qwen3-coder-flash",     # Faster, less expensive model
        "qwen-vl-max-latest",    # Vision model for image processing
        "qwen-vl-plus",          # Vision model
        "coder-model",           # Generic coder model
        "vision-model"           # Generic vision model
    ]
    
    print("Validating all known models...")
    print(f"Using endpoint: {resource_url or 'https://dashscope.aliyuncs.com/compatible-mode/v1'}")
    print()
    
    valid_models = []
    invalid_models = []
    
    for model in models_to_test:
        print(f"Testing model: {model}")
        is_valid = validate_model(model, access_token, resource_url)
        if is_valid:
            print(f"  Model {model}: ✓ Available")
            valid_models.append(model)
        else:
            print(f"  Model {model}: ✗ Not available")
            invalid_models.append(model)
        print()
    
    print("Validation Summary:")
    print(f" Valid models: {len(valid_models)}")
    for model in valid_models:
        print(f"    - {model}")
    
    print(f"  Invalid models: {len(invalid_models)}")
    for model in invalid_models:
        print(f"    - {model}")
    
    return True


if __name__ == "__main__":
    validate_all_models()
