from flask import Flask, request, jsonify
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)


keys = {}


def generate_aes_key(key_size):
    """Generates a random AES key."""
    if key_size not in (128, 192, 256):
        raise ValueError("Invalid AES key size. Must be 128, 192, or 256.")
    return os.urandom(key_size // 8)

def generate_rsa_key_pair(key_size):
    """Generates an RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_rsa_private_key(private_key):
    """Serializes an RSA private key to PEM format."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # No password for simplicity 
    )
    return pem

def serialize_rsa_public_key(public_key):
     """Serializes an RSA public key to PEM format"""
     pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
     )
     return pem

def deserialize_rsa_private_key(pem_data):
    """Deserializes an RSA private key from PEM format."""
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=None,  # No password used during serialization
        backend=default_backend()
    )
    return private_key
    
def deserialize_rsa_public_key(pem_data):
    """Deserializes an RSA public key from PEM format"""
    public_key = serialization.load_pem_public_key(
       pem_data,
       backend=default_backend()
    )
    return public_key


def aes_encrypt(key, plaintext):
    """Encrypts plaintext using AES-CBC with PKCS7 padding."""
    iv = os.urandom(16)  # Generate a random IV for CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # PKCS7 Padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode('utf-8')  # added IV for decryption


def aes_decrypt(key, ciphertext):
    """Decrypts AES-CBC ciphertext with PKCS7 padding."""
    ciphertext_bytes = base64.b64decode(ciphertext)
    iv = ciphertext_bytes[:16]  # Extract the IV
    ciphertext_no_iv = ciphertext_bytes[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext_no_iv) + decryptor.finalize()

    # PKCS7 Unpadding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode('utf-8')



def rsa_encrypt(public_key, plaintext):
    """Encrypts plaintext using RSA with OAEP padding."""
    ciphertext = public_key.encrypt(
        plaintext.encode('utf-8'),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode('utf-8')

def rsa_decrypt(private_key, ciphertext):
    """Decrypts RSA ciphertext with OAEP padding."""
    ciphertext_bytes = base64.b64decode(ciphertext)
    plaintext = private_key.decrypt(
        ciphertext_bytes,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

def generate_hash(data, algorithm):
    """Generates a hash of the given data using the specified algorithm."""

    if algorithm.upper() == "SHA-256":
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    elif algorithm.upper() == "SHA-512":
        digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    elif algorithm.upper() == "SHA3-256":
        digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    elif algorithm.upper() == "SHA3-512":
        digest = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
    elif algorithm.upper() == "BLAKE2B":
        digest = hashes.Hash(hashes.BLAKE2b(64), backend=default_backend())  # BLAKE2b requires digest size
    elif algorithm.upper() == "BLAKE2S":
        digest = hashes.Hash(hashes.BLAKE2s(32), backend=default_backend())  #BLAKE2s requires digest size
    else:
        raise ValueError("Unsupported hashing algorithm: {}".format(algorithm))

    digest.update(data.encode('utf-8'))
    hash_value = digest.finalize()
    return base64.b64encode(hash_value).decode('utf-8'), algorithm


def verify_hash(data, hash_value, algorithm):
    """Verifies if the given hash matches the data."""

    try:
        generated_hash, _ = generate_hash(data, algorithm)
        return generated_hash == hash_value, "Hash matches the data." if generated_hash == hash_value else "Hash does not match the data."
    except ValueError as e:
        return False, str(e)  # Handle unsupported algorithms during verification
    except Exception:
        return False, "An error occurred during hash verification"



@app.route('/generate-key', methods=['POST'])
def generate_key():
    """Generates a cryptographic key."""
    data = request.get_json()
    key_type = data.get('key_type')
    key_size = data.get('key_size')

    if not key_type or not key_size:
        return jsonify({'error': 'Missing key_type or key_size'}), 400
    if not isinstance(key_size, int):
         return jsonify({'error': 'key_size must be an integer'}), 400

    try:
        key_id = str(len(keys) + 1)  # Simple ID generation

        if key_type.upper() == 'AES':
            key_value = generate_aes_key(key_size)
            keys[key_id] = {'key': key_value, 'type': 'AES'}
            encoded_key = base64.b64encode(key_value).decode('utf-8')

        elif key_type.upper() == 'RSA':
             private_key, public_key = generate_rsa_key_pair(key_size)
             private_pem = serialize_rsa_private_key(private_key)
             public_pem = serialize_rsa_public_key(public_key)
             keys[key_id] = {'private_key': private_pem, 'public_key': public_pem,  'type': 'RSA'}
             #Return only publick key to user
             encoded_key = base64.b64encode(public_pem).decode('utf-8')

        else:
            return jsonify({'error': 'Invalid key_type'}), 400

        return jsonify({'key_id': key_id, 'key_value': encoded_key}), 201

    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': 'An unexpected error occurred: ' + str(e)}), 500


@app.route('/encrypt', methods=['POST'])
def encrypt():
    """Encrypts a message."""
    data = request.get_json()
    key_id = data.get('key_id')
    plaintext = data.get('plaintext')
    algorithm = data.get('algorithm')

    if not key_id or not plaintext or not algorithm:
        return jsonify({'error': 'Missing key_id, plaintext, or algorithm'}), 400

    if key_id not in keys:
        return jsonify({'error': 'Invalid key_id'}), 404

    key_data = keys[key_id]

    try:
        if algorithm.upper() == 'AES' and key_data['type'] == 'AES':
            ciphertext = aes_encrypt(key_data['key'], plaintext)
        elif algorithm.upper() == 'RSA' and key_data['type'] == 'RSA':
            public_key = deserialize_rsa_public_key(key_data.get('public_key'))
            ciphertext = rsa_encrypt(public_key, plaintext)
        else:
            return jsonify({'error': 'Invalid algorithm or key type mismatch'}), 400
        return jsonify({'ciphertext': ciphertext}), 200

    except Exception as e:
        return jsonify({'error': 'Encryption failed: ' + str(e)}), 500



@app.route('/decrypt', methods=['POST'])
def decrypt():
    """Decrypts a message."""
    data = request.get_json()
    key_id = data.get('key_id')
    ciphertext = data.get('ciphertext')
    algorithm = data.get('algorithm')

    if not key_id or not ciphertext or not algorithm:
        return jsonify({'error': 'Missing key_id, ciphertext, or algorithm'}), 400

    if key_id not in keys:
        return jsonify({'error': 'Invalid key_id'}), 404

    key_data = keys[key_id]

    try:
        if algorithm.upper() == 'AES' and key_data['type'] == 'AES':
            plaintext = aes_decrypt(key_data['key'], ciphertext)
        elif algorithm.upper() == 'RSA' and key_data['type'] == 'RSA':
            private_key = deserialize_rsa_private_key(key_data.get('private_key'))
            plaintext = rsa_decrypt(private_key, ciphertext)
        else:
            return jsonify({'error': 'Invalid algorithm or key type mismatch'}), 400
        return jsonify({'plaintext': plaintext}), 200

    except Exception as e:
        return jsonify({'error': 'Decryption failed: ' + str(e)}), 500


@app.route('/generate-hash', methods=['POST'])
def generate_hash_endpoint():
    """Generates a hash for the given data."""
    data = request.get_json()
    input_data = data.get('data')
    algorithm = data.get('algorithm')

    if not input_data or not algorithm:
        return jsonify({'error': 'Missing data or algorithm'}), 400

    try:
        hash_value, used_algorithm = generate_hash(input_data, algorithm)
        return jsonify({'hash_value': hash_value, 'algorithm': used_algorithm}), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': "An unexpected error occurred: "+ str(e)}), 500


@app.route('/verify-hash', methods=['POST'])
def verify_hash_endpoint():
    """Verifies if the given hash matches the data."""
    data = request.get_json()
    input_data = data.get('data')
    hash_value = data.get('hash_value')
    algorithm = data.get('algorithm')

    if not input_data or not hash_value or not algorithm:
        return jsonify({'error': 'Missing data, hash_value, or algorithm'}), 400

    try:
      is_valid, message = verify_hash(input_data, hash_value, algorithm)
      return jsonify({'is_valid': is_valid, 'message': message}), 200
    except Exception as e:
       return jsonify({"error":"An unexpected error occurred: "+str(e)}),500

if __name__ == '__main__':
    app.run(debug=True)  # Use debug=True for development only 
