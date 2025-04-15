# Secure Messaging API

A Flask-based secure messaging API that enables encrypted message storage and retrieval for users.

## Features

- User-specific message encryption using AES-256-CBC
- Secure key derivation from user IDs
- Message retrieval with automatic decryption
- Debug endpoint with fixed decryption logic
- Message expiry after 10 minutes (bonus feature)

## Setup and Installation

1. Clone the repository
2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```
   pip install flask cryptography
   ```
4. Run the application:
   ```
   flask run
   ```

## API Endpoints

### Store a Message
- **POST /messages**
  - Request body:
    ```json
    {
        "userId": "user123",
        "message": "Secret message"
    }
    ```
  - Response:
    ```json
    {
        "status": "Message stored successfully"
    }
    ```

### Retrieve Messages
- **GET /messages/:userId**
  - Response:
    ```json
    {
        "messages": [
            {
                "message": "Secret message",
                "timestamp": 1681560789
            }
        ]
    }
    ```

### Debug Decrypt Function
- **POST /debug/decrypt**
  - Request body:
    ```json
    {
        "encryptedData": "base64encodedencrypteddata",
        "key": "encryption_key"
    }
    ```
  - Response:
    ```json
    {
        "decryptedMessage": "Original message",
        "debugInfo": "Decryption successful"
    }
    ```

## Design Decisions

### 1. Encryption Method and Mode

I chose **AES-256-CBC** (Cipher Block Chaining) for the following reasons:
- It's explicitly required in the challenge requirements
- CBC mode provides security by ensuring identical plaintext blocks don't encrypt to the same ciphertext
- It's widely supported and considered secure when properly implemented with random IVs
- The 256-bit key length provides strong security against brute force attacks

### 2. Ensuring User-Specific Access

To ensure only the original user can access their messages:
- User-specific encryption keys are derived from user IDs using PBKDF2
- Each message is encrypted with the user's specific key
- Messages can only be decrypted with the correct user's key
- Server-side validation prevents users from accessing others' messages
- Error handling doesn't reveal information about other users' data

### 3. IV Storage and Extraction

For handling the Initialization Vector (IV):
- A random 16-byte IV is generated for each message encryption
- The IV is prepended to the encrypted data before base64 encoding
- When decrypting, the first 16 bytes are extracted as the IV
- The rest of the data is processed as the ciphertext
- This approach keeps the IV and ciphertext together without requiring additional storage

### 4. Prevention of User ID Spoofing

To prevent user ID spoofing:
- The API validates user IDs in route parameters
- In a production environment, I would implement proper authentication (JWT tokens)
- Access to user messages is controlled server-side
- Error messages are designed to not leak information about other users
- Message integrity is maintained through the encryption process
- A full production implementation would include authentication middleware to verify user identity

## Debugging Explanation

The original decryption function likely had these issues:
1. Incorrect handling of the IV (not extracting it from the encrypted data)
2. Improper padding management
3. Key length issues (AES-256 requires a 32-byte key)
4. Incorrect mode configuration
5. Data encoding/decoding issues

The fixed version:
- Properly extracts the IV from the encrypted data
- Handles PKCS#7 padding correctly
- Ensures the key is the correct length (32 bytes)
- Uses the correct AES-CBC mode configuration
- Properly converts between string and binary formats

## Assumptions and Constraints

- The application uses in-memory storage for simplicity. In production, a database would be used.
- The salt for key derivation is hardcoded. In production, this would be stored securely.
- This implementation includes message expiry as a bonus feature.
- Error handling is implemented but could be enhanced for production use.
- Additional security features like rate limiting would be needed in production.
- A real authentication system would be needed for a production application.
