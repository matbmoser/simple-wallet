from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timezone, UTC, timedelta
from utilities.operators import op
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from pyld import jsonld

from datetime import datetime
from dateutil.relativedelta import relativedelta
"""
Class to encrypt and decrypt data using asimetric RSA cryptography
Author: Mathias Brunkow Moser
"""
from base64 import urlsafe_b64encode
import json
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import hashlib
import sys 
import uuid
from didkit import issueCredential, keyToDID, keyToVerificationMethod
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode

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
    def generateJwkKey(kid,kty="OKP", crv="Ed25519"):
        return jwk.JWK.generate(kty=kty, crv=crv, size=256, kid=kid)

    @staticmethod
    def storeJwkKey(key, keyPath="./key.jwt"):
        op.to_json_file(source_object=key.export(as_dict=True), json_file_path=keyPath)

    @staticmethod
    def loadJwkKey(keyPath):
        return jwk.JWK.from_json(op.to_json(op.read_json_file(keyPath)))

    @staticmethod
    def signVerifiableCredential(private_key, data, issuer, id, exp):
        header = {
            'typ': 'JWT',
            'alg': 'EdDSA',
            'crv': 'Ed25519',
            'kid': 'bf7f1756f8fcc493de7c2b1362f1bdc986e836e953f66bc622b097126f91abcb'
        }
        payload = {
            'sub': 'data-wallet',
            'exp': exp, #expire date
            'iat': datetime.timestamp(), #issue date
            'vc': data,
            'jti': id, # Id from the ## uuid
            'iss': issuer
        }
        to_sign = cryptool.encodeBase64NoPadding(json.dumps(header).encode('utf-8')) + b'.' + cryptool.encodeBase64NoPadding(json.dumps(payload).encode('utf-8'))
        signature = cryptool.encodeBase64NoPadding(private_key.sign(to_sign))
        jwt = (to_sign + b'.' + signature).decode()
        return jwt

    @staticmethod
    def urlToDidWeb(url):
        newUrl = url
        newUrl = newUrl.replace("https://", "")
        newUrl = newUrl.replace("http://", "")
        newUrl = newUrl.replace("/", ":")
        return "did:web:"+newUrl.removesuffix(":")

    @staticmethod
    def issueJwtVerifiableCredential(url, methodId, issuerId, private_key, credential):
        didWeb = cryptool.urlToDidWeb(url=url)

        issuance_date = datetime.now(UTC).replace(microsecond=0)
        expiration_date = issuance_date + timedelta(weeks=24)
        issuerDid = f"{didWeb}:{issuerId}"
        id = uuid.uuid4()
        credential["id"] = f"urn:uuid:{id}"
        credential["issuer"] = issuerDid
        credential["issuanceDate"] = issuance_date.isoformat() + "Z"
        credential["expirationDate"] = expiration_date.isoformat() + "Z"
        header = {
            'typ': 'vc+ld',
            'b64': False,
            'crv': 'Ed25519'
        }

        
        jwstoken = jws.JWS(payload=str(credential).encode("utf-8"))
        jwstoken.add_signature(key=private_key, alg="EdDSA", header=json_encode({"kid": private_key.thumbprint()}))
        
        sig = jwstoken.serialize()
        print(sig)
        credential["proof"] = {
            "type": "JsonWebSignature2020",
            "proofPurpose": "assertionMethod",
            "verificationMethod": f"{issuerDid}#{methodId}",
            "created": issuance_date.isoformat() + "Z",
            "jws": sig
        }
        return credential

    @staticmethod
    def issueVerifiableCredential(url, methodId, issuerId, private_key, credential):
        didWeb = cryptool.urlToDidWeb(url=url)

        issuance_date = datetime.now(UTC).replace(microsecond=0)
        expiration_date = issuance_date + timedelta(weeks=24)
        issuerDid = f"{didWeb}:{issuerId}"
        id = uuid.uuid4()
        credential["id"] = f"urn:uuid:{id}"
        credential["issuer"] = issuerDid
        credential["issuanceDate"] = issuance_date.isoformat() + "Z"
        credential["expirationDate"] = expiration_date.isoformat() + "Z"
        header = {
            'typ': 'vc+ld',
            'b64': False,
            'crv': 'Ed25519'
        }
        to_sign = cryptool.encodeBase64NoPadding(json.dumps(header).encode('utf-8')) + b'.' + cryptool.encodeBase64NoPadding(json.dumps(credential).encode('utf-8'))
        signature = cryptool.encodeBase64NoPadding(private_key.sign(to_sign))
        jws = (cryptool.encodeBase64NoPadding(json.dumps(header).encode('utf-8')) + b'..' + signature).decode()
        credential["proof"] = {
            "type": "JsonWebSignature2020",
            "proofPurpose": "assertionMethod",
            "verificationMethod": f"{issuerDid}#{methodId}",
            "created": issuance_date.isoformat() + "Z",
            "jws": jws
        }
        return credential


    @staticmethod
    def signJwsVerifiableCredential(request,private_key, data):
        header = {
            'typ': 'vc+ld',
            'b64': False,
            'crv': 'Ed25519'
        }
        to_sign = cryptool.encodeBase64NoPadding(json.dumps(header).encode('utf-8')) + b'.' + cryptool.encodeBase64NoPadding(json.dumps(data).encode('utf-8'))
        signature = cryptool.encodeBase64NoPadding(private_key.sign(to_sign))
        jwt = (cryptool.encodeBase64NoPadding(json.dumps(header).encode('utf-8')) + b'..' + signature).decode()
        return jwt


    @staticmethod
    def signVerifiableCredential(private_key, data):
        return cryptool.encodeBase64NoPadding(private_key.sign(json.dumps(data).encode('utf-8'))).decode()

    @staticmethod
    def signJwtVerifiableCredential(private_key, data, issuer, id):
        
        expanded = None
        try:
            expanded = jsonld.expand(data)
        except:
            raise Exception('Impossible to sign the verifiable credential because it can not be expanded!')    
        
        if(expanded is None):
            raise Exception('No content was expanded in the verifiable credential!')    

        header = {
            'typ': 'vc+jwt',
            'alg': 'EdDSA',
            'crv': 'Ed25519',
        }
        payload = {
            'sub': 'data-wallet',
            'vc': data,
            'jti': id, # Id from the 
            'iss': issuer
        }
        to_sign = cryptool.encodeBase64NoPadding(json.dumps(header).encode('utf-8')) + b'.' + cryptool.encodeBase64NoPadding(json.dumps(payload).encode('utf-8'))
        signature = cryptool.encodeBase64NoPadding(private_key.sign(to_sign))
        jwt = (to_sign + b'.' + signature).decode()
        return jwt

    @staticmethod
    def generateJwkPrivateKey():
        return Ed25519PrivateKey.generate()
    
    @staticmethod
    def privateJwkKeyToPemString(private_key):
        return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
    @staticmethod
    def publicJwkKeyToPemString(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
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
    def sha512(input):
        return hashlib.sha512(str(input).encode('utf-8')).hexdigest()

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
    def storePrivateKey(private_key, keysDir="./keys"):
        if(not op.path_exists(keysDir)):
            op.make_dir(keysDir)
        with open(f"{keysDir}/private_key.pem", 'wb') as f:
            f.write(private_key)

    @staticmethod
    def storePublicKey(public_key, keysDir="./keys"):
        if(not op.path_exists(keysDir)):
            op.make_dir(keysDir)
        with open(f"{keysDir}/public_key.pem", 'wb') as f:
            f.write(public_key)

    
    @staticmethod
    def storeCredential(id, credential, issuerId, dir="./credentials"):
        if(not op.path_exists(dir)):
            op.make_dir(dir)

        completeDir = f"{dir}/{issuerId}"
        if(not op.path_exists(completeDir)):
            op.make_dir(completeDir)

        op.to_json_file(credential, f"{completeDir}/{id}.jsonld")



    @staticmethod
    def storeKeys(public_key, private_key, keysDir="."):

        with open(f"{keysDir}/private_key.pem", 'wb') as f:
            f.write(private_key)
        
        with open(f"{keysDir}/public_key.pem", 'wb') as f:
            f.write(public_key)
            
    @staticmethod
    def loadPrivateKey(keysDir="./keys"):
        if(not op.path_exists(keysDir)):
            op.print_log(logType="CRITICAL", messageStr=f"Path [{keysDir}] not found. cryptool.loadKeys()")
            return None, None
        
        with open(f"{keysDir}/private_key.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
        return private_key
    
    @staticmethod
    def loadPublicKey(keysDir="./keys"):
        if(not op.path_exists(keysDir)):
            op.print_log(logType="CRITICAL", messageStr=f"Path [{keysDir}] not found. cryptool.loadKeys()")
            return None, None
        
        with open(f"{keysDir}/public_key.pem", "rb") as key_file:
                private_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
        return private_key
    
    @staticmethod
    def loadKeys(id, base_dir="./keys"):
        keysDir = base_dir+"/"+id
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