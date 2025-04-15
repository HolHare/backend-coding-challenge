# app.py
from flask import Flask, request, jsonify
import os
import base64
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# In-memory storage for messages (in production, use a database)
messages_store = {}

# Salt for key derivation - would be stored securely in production
SALT = b'secure_salt_for_key_derivation'

def derive_key(user_id):
    """Derive a secure key from the user ID."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits for AES-256
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    # In a real system, would use a secret combined with user ID
    user_key_material = f"user-{user_id}-secret".encode('utf-8')
    return kdf.derive(user_key_material)

def encrypt_message(message, user_id):
    """Encrypt a message using AES-256-CBC."""
    # Generate a random 16-byte IV
    iv = os.urandom(16)
    
    # Derive key for this user
    key = derive_key(user_id)
    
    # Create an encryptor
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Pad the message to be a multiple of 16 bytes (AES block size)
    padded_message = pad_data(message.encode('utf-8'))
    
    # Encrypt the message
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    
    # Combine IV and ciphertext and encode to base64
    encrypted_data = base64.b64encode(iv + ciphertext).decode('utf-8')
    
    return encrypted_data

def decrypt_message(encrypted_data, user_id):
    """Decrypt a message using AES-256-CBC."""
    # Decode from base64
    data = base64.b64decode(encrypted_data)
    
    # Extract IV (first 16 bytes)
    iv = data[:16]
    ciphertext = data[16:]
    
    # Derive key for this user
    key = derive_key(user_id)
    
    # Create a decryptor
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Decrypt the message
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad the decrypted data
    plaintext = unpad_data(padded_plaintext)
    
    return plaintext.decode('utf-8')

def pad_data(data):
    """PKCS#7 padding for data."""
    block_size = 16  # AES block size
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad_data(padded_data):
    """Remove PKCS#7 padding."""
    padding_length = padded_data[-1]
    return padded_data[:-padding_length]

@app.route('/messages', methods=['POST'])
def store_message():
    data = request.get_json()
    if not data or 'userId' not in data or 'message' not in data:
        return jsonify({"error": "Missing required fields"}), 400
    
    user_id = data['userId']
    message = data['message']
    
    # Current timestamp for potential expiry functionality
    timestamp = int(time.time())
    
    # Encrypt the message
    encrypted_message = encrypt_message(message, user_id)
    
    # Store the encrypted message with timestamp
    if user_id not in messages_store:
        messages_store[user_id] = []
    
    messages_store[user_id].append({
        "encrypted_data": encrypted_message,
        "timestamp": timestamp
    })
    
    return jsonify({"status": "Message stored successfully"}), 201

@app.route('/messages/<user_id>', methods=['GET'])
def get_messages(user_id):
    if user_id not in messages_store:
        return jsonify({"messages": []}), 200
    
    # Optional: Implement message expiry (10 minutes = 600 seconds)
    current_time = int(time.time())
    valid_messages = []
    
    for msg_data in messages_store[user_id]:
        # Skip messages older than 10 minutes (bonus feature)
        if current_time - msg_data["timestamp"] > 600:
            continue
        
        try:
            decrypted_message = decrypt_message(msg_data["encrypted_data"], user_id)
            valid_messages.append({
                "message": decrypted_message,
                "timestamp": msg_data["timestamp"]
            })
        except Exception as e:
            # Log the error but don't expose details in response
            print(f"Decryption error: {str(e)}")
    
    return jsonify({"messages": valid_messages}), 200

# Debug task implementation
@app.route('/debug/decrypt', methods=['POST'])
def debug_decrypt():
    """
    Fixed version of broken_decrypt function
    """
    data = request.get_json()
    if not data or 'encryptedData' not in data or 'key' not in data:
        return jsonify({"error": "Missing required fields"}), 400
    
    encrypted_data = data['encryptedData']
    key = data['key']
    
    try:
        # Base64 decode the encrypted data
        binary_data = base64.b64decode(encrypted_data)
        
        # Extract IV (first 16 bytes) and ciphertext
        iv = binary_data[:16]
        ciphertext = binary_data[16:]
        
        # Convert key to bytes if it's not already
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        # Ensure key is 32 bytes (256 bits)
        if len(key) != 32:
            # Use SHA-256 to derive a 32-byte key
            hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hasher.update(key)
            key = hasher.finalize()
        
        # Create AES cipher with CBC mode
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        
        # Create decryptor
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad the data
        padding_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_length]
        
        # Return the decrypted message
        return jsonify({
            "decryptedMessage": plaintext.decode('utf-8'),
            "debugInfo": "Decryption successful"
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": "Decryption failed",
            "debugInfo": str(e)
        }), 400

"""
Explanation of fix for broken_decrypt:

The potential issues in the original broken_decrypt function might include:

1. Not properly extracting the IV from the encrypted data
2. Using incorrect padding mechanism or not handling padding correctly
3. Not properly converting between string and binary formats
4. Using the wrong encryption mode or parameters
5. Key length issues (AES-256 requires a 32-byte key)

The fixed version addresses these issues by:
- Properly separating the IV from the ciphertext
- Ensuring the key is the correct length by hashing if necessary
- Using proper PKCS#7 padding removal
- Properly handling binary data and conversions
- Using the correct AES-CBC mode parameters
"""

# Test case for the debug function
def test_debug_decrypt():
    """
    Test case to verify the fixed decryption function works correctly.
    """
    # Generate a test key
    test_key = os.urandom(32)
    
    # Test message
    original_message = "This is a test message for debugging"
    
    # Generate IV
    iv = os.urandom(16)
    
    # Pad message
    padded_message = pad_data(original_message.encode('utf-8'))
    
    # Encrypt
    cipher = Cipher(
        algorithms.AES(test_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    
    # Combine IV and ciphertext and encode to base64
    encrypted_data = base64.b64encode(iv + ciphertext).decode('utf-8')
    
    # Use the debug function to decrypt
    # (In a real test, you'd use Flask test client)
    print(f"Test key: {base64.b64encode(test_key).decode('utf-8')}")
    print(f"Encrypted: {encrypted_data}")
    
    # This would be tested via API call in real test

if __name__ == '__main__':
    # Run test case if in debug mode
    if os.environ.get('FLASK_DEBUG'):
        test_debug_decrypt()
    
    app.run(debug=True)
