from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timezone
from operators import op
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat


"""
Class to encrypt and decrypt data using asimetric RSA cryptography
Author: Mathias Brunkow Moser
"""
from base64 import urlsafe_b64encode
import json
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key


class cryptool:
    @staticmethod
    def encodeBase64NoPadding(to_encode):
        return urlsafe_b64encode(to_encode).rstrip(b'=')

    @staticmethod
    def generateJwkPublicKey(private_key):
        return private_key.public_key().public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
    
    @staticmethod
    def loadPrivateKey(private_key_content):
            private_key = load_pem_private_key(
            private_key_content, password=None, backend=default_backend())
            return private_key


    @staticmethod
    def signVerifiableCredential(private_key, data, issuer, id):
        header = {
            'typ': 'JWT',
            'alg': 'EdDSA',
            'crv': 'Ed25519',
        }
        payload = {
            'sub': 'data-wallet',
            'vc': data,
            'jti': id, # Id from the 
            'iss': issuer
        }
        to_sign = cryptool.b64encode_nopadding(json.dumps(header).encode('utf-8')) + b'.' + cryptool.b64encode_nopadding(json.dumps(payload).encode('utf-8'))
        signature = cryptool.b64encode_nopadding(private_key.sign(to_sign))
        jwt = (to_sign + b'.' + signature).decode()
        return jwt

    @staticmethod
    def generateJwkPrivateKey():
        return Ed25519PrivateKey.generate()
    
    def privateJwkKeyToString(private_key):
        return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )


    @staticmethod
    def generatePrivateKey(keySize=2048, publicExponent=65537):
        # Generamos clave privada
        return rsa.generate_private_key(
            public_exponent=publicExponent,
            key_size=keySize
        )
        
    @staticmethod  
    def generatePublicKey(private_key):
        return private_key.public_key()
    
    @staticmethod
    def generateKeys(keySize=2048, publicExponent=65537, string=False):
        # Generamos clave privada
        private_key = cryptool.generatePrivateKey(publicExponent=publicExponent,keySize=keySize)
        
        # Generamos la clave publica
        public_key = cryptool.generatePublicKey(private_key)
        
        # Storing the keys
        strPriv = cryptool.privateKeyToString(private_key=private_key)

        strPub = cryptool.publicKeyToString(public_key=public_key)
            
        if(string):
            return strPub, strPriv
        
        return public_key, private_key
    
    @staticmethod
    def privateKeyToString(private_key):
        return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
   
    @staticmethod
    def publicKeyToString(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    
    @staticmethod
    def storeKeys(public_key, private_key, dir="."):

        with open(f"{dir}/private_key.pem", 'wb') as f:
            f.write(private_key)
        
        with open(f"{dir}/public_key.pem", 'wb') as f:
            f.write(public_key)
            
    
    @staticmethod
    def loadKeys(id):
        keysDir = f"keys/{id}"
        if(not op.pathExists(keysDir)):
            op.printLog(logType="CRITICAL", messageStr=f"Path [{keysDir}] not found. cryptool.loadKeys()")
            return None, None
        
        with open(f"{keysDir}/private_key.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
        with open(f"{keysDir}/public_key.pem", "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
        return private_key, public_key
    
    @staticmethod
    def loadPublicKeyFromString(stringKey):
        public_key = serialization.load_pem_public_key(
                stringKey,
                backend=default_backend()
            )
        return public_key
    
    @staticmethod
    def loadPrivateKeyFromString(stringKey):
        private_key = serialization.load_pem_private_key(
                    stringKey,
                    password=None,
                    backend=default_backend()
                )
        return private_key
    
    @staticmethod
    def encrypt(message, public_key, encoding="utf-8"):
        
        if type(public_key) == bytes or type(public_key) == str:
            public_key = cryptool.loadPublicKeyFromString(public_key)
            
        return public_key.encrypt(
                bytes(message, encoding=encoding),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                    )
                )

    @staticmethod
    def decrypt(encrypted, private_key, encoding="utf-8"):
        if type(private_key) == bytes or type(private_key) == str:
            private_key = cryptool.loadPrivateKeyFromString(private_key)
        
        return str(private_key.decrypt(
                encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                    )
                ), encoding=encoding)


if __name__ == '__main__':
    ## Test para generar claves, encriptar y desencriptar
    idName="fsds12s"
    
    public, private = cryptool.generateKeys(idName, string=True)

    # Contraseña de acceso a la clave privada
    print("Claves generadas!")
    print(f"PublicKey = [{public}]\n\n")
    print(f"PrivateKey = [{private}]\n\n")
    
    # Cargamos las claves en formato objeto RSA
    public_key = cryptool.loadPublicKeyFromString(public)
    private_key = cryptool.loadPrivateKeyFromString(private)
    
    timestamp = str(datetime.timestamp(datetime.now(timezone.utc)))
    text = '{"clt-time":"'+timestamp+'", flag":"IN", "matricula": "1245-LDF"}'

    print(f"Mensaje Antes de Encriptar: [{text}]\n\n")
    
    cypher = cryptool.encrypt(text, public_key) # Encriptamos con la clave publica

    print(f"Mensaje Cifrado = [{cypher}]\n\n")

    decrypted = cryptool.decrypt(cypher, private_key) # Desencriptamos con la clave privada

    print(f"Texto Desencriptado = [{decrypted}]")