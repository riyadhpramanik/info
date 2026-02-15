from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
from flask import Flask, jsonify, request
from data_pb2 import AccountPersonalShowInfo
from google.protobuf.json_format import MessageToDict
import uid_generator_pb2
import threading
import time
import json
import os

app = Flask(__name__)

# Global JWT token and lock
jwt_token = None
jwt_lock = threading.Lock()

# Path to optional default token file (JSON). If present and contains a token,
# the server will use that token for the "default" region and will NOT attempt
# to fetch/refresh it from remote endpoints repeatedly.
DEFAULT_TOKEN_FILE = os.path.join(os.path.dirname(__file__), 'default.json')

# Load token from default.json if available. The file format expected is a list
# of objects like: [{ "token": "<jwt>" }]
def load_default_token_from_file():
    global jwt_token
    if not os.path.isfile(DEFAULT_TOKEN_FILE):
        return None
    try:
        with open(DEFAULT_TOKEN_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                token = data[0].get('token')
                if token:
                    with jwt_lock:
                        jwt_token = token
                    print('Loaded default JWT token from', DEFAULT_TOKEN_FILE)
                    return token
    except Exception as e:
        print('Failed to load default token file:', e)
    return None


def extract_token_from_response(data, region):
    if region == "IND":
        if data.get('status') in ['success', 'live']:
            return data.get('token')
    elif region in ["BR", "US", "SAC", "NA"]:
        if isinstance(data, dict) and 'token' in data:
            return data['token']
    else:
        if data.get('status') == 'success':
            return data.get('token')
    return None


def get_jwt_token_sync(region):
    """Synchronously fetch a JWT token from remote endpoints for non-default regions.
    This function **does** update the global jwt_token variable.
    """
    global jwt_token
    endpoints = {
        "IND": "https://jwt-token-api-by-ajay-seven.vercel.app/token?uid=4422013059&password=9A14867BBA0091781F5BBAC54DDC945B7C3B317B5C35E01AA62BC67DD910F22F",
        "BR": "https://jwt-token-api-by-ajay-seven.vercel.app/token?uid=4422013059&password=9A14867BBA0091781F5BBAC54DDC945B7C3B317B5C35E01AA62BC67DD910F22F",
        "US": "https://jwt-token-api-by-ajay.vercel.app/token?uid=4422013059&password=9A14867BBA0091781F5BBAC54DDC945B7C3B317B5C35E01AA62BC67DD910F22F",
        "SAC": "https://jwt-token-api-by-ajay.vercel.app/token?uid=4422013059&password=9A14867BBA0091781F5BBAC54DDC945B7C3B317B5C35E01AA62BC67DD910F22F",
        "NA": "https://jwt-token-api-by-ajay.vercel.app/token?uid=4422013059&password=9A14867BBA0091781F5BBAC54DDC945B7C3B317B5C35E01AA62BC67DD910F22F",
        "default": "https://jwt-token-api-by-ajay-seven.vercel.app/token?uid=4211919159&password=5B3859B15A4EADAC15E6C1CBEC1C077D96C4997F7EDDC6796F1BAAA3C00F8E43"
    }
    url = endpoints.get(region, endpoints["default"])
    with jwt_lock:
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                token = extract_token_from_response(data, region)
                if token:
                    jwt_token = token
                    print(f"JWT Token for {region} updated successfully: {token[:50]}...")
                    return jwt_token
                else:
                    print(f"Failed to extract token from response for {region}")
            else:
                print(f"Failed to get JWT token for {region}: HTTP {response.status_code}")
        except Exception as e:
            print(f"Request error for {region}: {e}")
    return None


def ensure_jwt_token_sync(region):
    """Return a JWT token for the region.
    If region == 'DEFAULT' and a token was loaded from default.json, use that and
    do NOT attempt to refresh it automatically. For other regions, fetch synchronously
    when missing.
    """
    global jwt_token
    region = (region or 'default').lower()
    if region == 'default':
        # If token already loaded from default.json, use it.
        if jwt_token:
            return jwt_token
        # If not loaded, try loading from file once.
        t = load_default_token_from_file()
        if t:
            return t
        # fallback: try remote endpoint (only if user really wants)
        print("Default region requested but no default.json token found — attempting remote fetch as fallback.")
        return get_jwt_token_sync('default')

    # For non-default regions, if token missing fetch it synchronously
    if not jwt_token:
        return get_jwt_token_sync(region.upper())
    return jwt_token


def jwt_token_updater(region):
    """Background updater (keeps fetching token every 5 minutes). We don't auto-start
    this for the default region when a local default.json token exists.
    """
    while True:
        get_jwt_token_sync(region)
        time.sleep(300)


def get_api_endpoint(region):
    endpoints = {
        "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
        "BR": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "US": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "NA": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "default": "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
    }
    return endpoints.get(region, endpoints["default"])

# Default AES key/iv (can be overridden by query params)
key = "Yg&tc%DEuh6%Zc^8"
iv = "6oyZDr22E3ychjM%"


def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv = iv.encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()


def apis(idd, region):
    global jwt_token
    token = ensure_jwt_token_sync(region)
    if not token:
        raise Exception(f"Failed to get JWT token for region {region}")

    endpoint = get_api_endpoint(region)
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Expect': '100-continue',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB52',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    try:
        data = bytes.fromhex(idd)
        response = requests.post(
            endpoint,
            headers=headers,
            data=data,
            timeout=10
        )
        response.raise_for_status()
        return response.content.hex()
    except requests.exceptions.RequestException as e:
        print(f"API request to {endpoint} failed: {e}")
        raise


@app.route('/accinfo', methods=['GET'])
def get_player_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'default').upper()
        custom_key = request.args.get('key', key)
        custom_iv = request.args.get('iv', iv)
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400

        # For default region we will use default.json token if present — no background updater.
        # For other regions we fetch token synchronously when needed.
        # IMPORTANT: we DO NOT start a new background thread per request.

        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        protobuf_data = message.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)
        api_response = apis(encrypted_hex, region)
        if not api_response:
            return jsonify({"error": "Empty response from API"}), 400
        message_pb = AccountPersonalShowInfo()
        message_pb.ParseFromString(bytes.fromhex(api_response))
        result = MessageToDict(message_pb)
        result['Owners'] = ['agajayofficial']
        return jsonify(result)
    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400
    except Exception as e:
        print(f"Error processing request: {e}")
        return jsonify({"error": f"Failure to process the data: {str(e)}"}), 500


@app.route('/favicon.ico')
def favicon():
    return '', 404


if __name__ == "__main__":
    # Try to pre-load default token from default.json so the server uses it immediately.
    load_default_token_from_file()
    # IMPORTANT: do not start jwt_token_updater thread for default region — this keeps the
    # "default" region behaviour stable and avoids repeated remote token generation.

    # If you want a background updater for non-default regions, you can start one here,
    # e.g. threading.Thread(target=jwt_token_updater, args=("US",), daemon=True).start()

    app.run(host="0.0.0.0", port=5552)
