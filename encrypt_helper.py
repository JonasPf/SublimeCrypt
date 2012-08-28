"""
Modified version of the demonstration from the pythonaes package.

Compared to the original version this file:
    - Encrypts/Decrypts strings instead of files
    - Uses MD5 to check if decryption was successful

Format of the encrypted string:
    1. 32 bytes: salt used for the encryption
    2.  4 bytes: size of the original string
    4. Rest: encrypted message. When decrypted, the first 16 bytes contain the md5 of the original string 

Modified work Copyright (c) 2012, Jonas Pfannschmidt
Original work Copyright (c) 2010, Adam Newman http://www.caller9.com/
Licensed under the MIT license http://www.opensource.org/licenses/mit-license.php
"""
import os
import hashlib
import struct
import getopt
import sys
import time
import hashlib

from aespython import key_expander, aes_cipher, cbc_mode

class AESHelper:
    def __init__(self):
        self._salt = None
        self._iv = None
        self._key = None
        self._python3 = sys.version_info > (3, 0)
    
    def new_salt(self):
        self._salt = os.urandom(32)
    
    def set_iv(self, iv):
        self._iv = iv
    
    def set_key(self, key):
        self._key = key
    
    def split_len(self, seq, length): 
        return [seq[i:i+length] for i in range(0, len(seq), length)] 

    def create_key_from_password(self, password):
        if self._salt is None:
            return
        sha512 = hashlib.sha512(password.encode('utf-8') + self._salt[:16]).digest()
        self._key = bytearray(sha512[:32])
        self._iv = [i ^ j for i, j in zip(bytearray(self._salt[16:]), bytearray(sha512[32:48]))]
    
    def fix_bytes(self, byte_list):
        #bytes function is broken in python < 3. It appears to be an alias to str()
        #Either that or I have insufficient magic to make it work properly. Calling bytes on my
        #array returns a string of the list as if you fed the list to print() and captured stdout
        if self._python3:
            return bytes(byte_list)
        tmpstr=''
        for i in byte_list:
            tmpstr += chr(i)
        return tmpstr
    
    def decrypt_string(self, in_string, password):
        size_length = struct.calcsize('=L')
        hash_length = 16
        salt_length = 32
        size_start  = salt_length
        msg_start   = size_start + size_length

        # Generate key and iv using salt from string.
        self._salt = in_string[:salt_length]
        self.create_key_from_password (password)
            
        #Initialize encryption using key and iv
        key_expander_256 = key_expander.KeyExpander(256)
        expanded_key = key_expander_256.expand(self._key)
        aes_cipher_256 = aes_cipher.AESCipher(expanded_key)
        aes_cbc_256 = cbc_mode.CBCMode(aes_cipher_256, 16)
        aes_cbc_256.set_iv(self._iv)

        size = struct.unpack('L', in_string[size_start:size_start+size_length])[0]

        # Decrypt
        out = ""
        chunks = self.split_len(in_string[msg_start:], 16)
        for chunk in chunks:
            out_data = self.fix_bytes(aes_cbc_256.decrypt_block(list(bytearray(chunk))))
            #At end of the string, if end of original string is within < 16 bytes slice it out.
            if size - len(out) < 16:
                out += out_data[:size - len(out)]
            else:
                out += out_data

        self._salt = None

        # Check md5
        md5hash = out[:hash_length]
        out = out[hash_length:]

        if (md5hash == self.create_hash(out)):
            return out
        else:
            return False
        
    def encrypt_string(self, input_data, password): 
        #If a password is provided, generate new salt and create key and iv
        self.new_salt()
        self.create_key_from_password(password)

        #Initialize encryption using key and iv
        key_expander_256 = key_expander.KeyExpander(256)
        expanded_key = key_expander_256.expand(self._key)
        aes_cipher_256 = aes_cipher.AESCipher(expanded_key)
        aes_cbc_256 = cbc_mode.CBCMode(aes_cipher_256, 16)
        aes_cbc_256.set_iv(self._iv)

        # Add hash for validating successful decryption
        input_data = self.create_hash(input_data) + input_data
        
        # Add prefix
        output = self._salt
        output += struct.pack('=L', len(input_data))

        # Encrypt
        chunks = self.split_len(input_data, 16)
        for chunk in chunks:
            output += self.fix_bytes(aes_cbc_256.encrypt_block(bytearray(chunk)))
                
        return output

    def create_hash(self, input_data):
        md5 = hashlib.md5()
        md5.update(input_data)
        return md5.digest()
    
def main():
    helper = AESHelper()
    cipher = helper.encrypt_string("test", "123")
    
    print("Cipher: %s" % cipher)
    
    text = helper.decrypt_string(cipher, "123")

    print("Text:   %s" % text)

if __name__ == "__main__":
    main()
