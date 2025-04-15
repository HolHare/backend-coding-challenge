# test_api.py
import requests
import json
import time

BASE_URL = "http://127.0.0.1:5000"

def test_store_message():
    url = f"{BASE_URL}/messages"
    payload = {
        "userId": "user123",
        "message": "This is a secret message!"
    }
    
    response = requests.post(url, json=payload)
    print(f"Store message response: {response.status_code}")
    print(response.json())
    
    return response.status_code == 201

def test_get_messages(user_id="user123"):
    url = f"{BASE_URL}/messages/{user_id}"
    
    response = requests.get(url)
    print(f"Get messages response: {response.status_code}")
    print(json.dumps(response.json(), indent=2))
    
    return response.status_code == 200

def test_debug_endpoint():
    # This would typically use a known encrypted message and key
    # for demonstration purposes
    
    # In a real test, we'd need to have encrypted data and its key
    url = f"{BASE_URL}/debug/decrypt"
    
    # You'd need real encrypted data here
    payload = {
        "encryptedData": "YOUR_ENCRYPTED_DATA_HERE",
        "key": "YOUR_KEY_HERE"
    }
    
    # This is just a placeholder - you'd need actual encrypted data and key
    print("Debug endpoint test requires actual encrypted data - skipping")
    
    # response = requests.post(url, json=payload)
    # print(f"Debug decrypt response: {response.status_code}")
    # print(response.json())
    
    return True

def run_tests():
    print("=== Starting API Tests ===")
    
    # Test message storage
    if test_store_message():
        print("✅ Store message test passed")
    else:
        print("❌ Store message test failed")
    
    print("\n")
    
    # Wait a moment for processing
    time.sleep(1)
    
    # Test message retrieval
    if test_get_messages():
        print("✅ Get messages test passed")
    else:
        print("❌ Get messages test failed")
    
    print("\n")
    
    # Test debug endpoint
    if test_debug_endpoint():
        print("➖ Debug endpoint test skipped - needs actual data")
    else:
        print("❌ Debug endpoint test failed")
    
    print("\n=== Tests Complete ===")

if __name__ == "__main__":
    run_tests()
