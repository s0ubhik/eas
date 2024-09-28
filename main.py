from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

class EAS:
    BLOCK_SIZE = 16
    
    @staticmethod
    def pkcs7_pad(data):
        pad_length = EAS.BLOCK_SIZE - (len(data) % EAS.BLOCK_SIZE)
        padding = chr(pad_length) * pad_length
        return data + padding

    @staticmethod
    def pkcs7_unpad(data):
        pad_length = ord(data[-1])
        return data[:-pad_length]

    @staticmethod
    def encrypt(data, key):
        key = key.ljust(32)[:32] 
        
        padded_data = EAS.pkcs7_pad(data)
        
        iv = get_random_bytes(16)  # Generate a random IV
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        
        ciphertext = cipher.encrypt(padded_data.encode('utf-8'))
        
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    @staticmethod
    def decrypt(ciphertext, key):
        key = key.ljust(32)[:32]
        
        data = base64.b64decode(ciphertext)
        iv = data[:16] 
        encrypted_data = data[16:]
        
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        decrypted_padded_data = cipher.decrypt(encrypted_data)
        
        decrypted_data = EAS.pkcs7_unpad(decrypted_padded_data.decode('utf-8'))
        return decrypted_data
