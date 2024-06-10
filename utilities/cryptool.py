from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timezone, UTC, timedelta
from utilities.operators import op
from utilities.httpUtils import HttpUtils
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from pyld import jsonld
from urllib.parse import urljoin, urlparse

from datetime import datetime
from dateutil.relativedelta import relativedelta
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
"""
Class to encrypt and decrypt data using asimetric RSA cryptography
Author: Mathias Brunkow Moser
"""
from base64 import urlsafe_b64encode, urlsafe_b64decode
import json
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import hashlib
import sys 
import uuid
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode
import logging

logger = logging.getLogger('staging')

SUPPORTED_VERIFICATION_TYPES = ["JsonWebSignature2020"]

import copy

class cryptool:
    @staticmethod
    def encodeBase64NoPadding(to_encode):
        return urlsafe_b64encode(to_encode).rstrip(b'=')

    @staticmethod
    def decodeBase64NoPadding(to_decode):
        return urlsafe_b64decode(to_decode+"==")

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
    def loadJwkPublicKey(public_key_pem):
        return jwk.JWK.from_pem(public_key_pem)


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
        """
            Created according to: https://w3c-ccg.github.io/did-method-web/#did-method-operations
        """
        newUrl = url
        newUrl = newUrl.replace("https://", "")
        newUrl = newUrl.replace("http://", "")
        newUrl = newUrl.replace(":", "%3A")
        newUrl = newUrl.replace("/", ":")
        return "did:web:"+newUrl.removesuffix(":")

    @staticmethod
    def resolveDidWeb(did_web):
        """
            Resolved according to: https://w3c-ccg.github.io/did-method-web/#did-method-operations
        """
        newUrl = did_web
        newUrl = newUrl.replace("did:web:", "")
        newUrl = newUrl.replace(":","/")
        newUrl = newUrl.replace("%3A",":")
        if("localhost" in newUrl) or ("127.0.0.1" in newUrl):
            newUrl = "http://" + newUrl
        else:
            newUrl = "https://" + newUrl
    
        path = urlparse(newUrl).path
        if(path is None) or (path == ""):
            path = "/.well-known"
        newUrl = urljoin(newUrl, path) 
        return newUrl + "/did.json"
    
    @staticmethod
    def issueEd25519VerifiableCredential(walletUrl, methodId, issuerId, expirationTimedelta, private_key, credential):
        ## Generate the DID web for the wallet url
        didWeb = cryptool.urlToDidWeb(url=walletUrl)

        ## Expand verifiable credential to check if its a valid json-ld
        try:
            expandedCredential = jsonld.expand(credential)
        except:
            raise Exception("It was not possible to expand the json-ld credential! Invalid JSON-LD!")

        ## Generate checksum for the expanded credential
        checksum = cryptool.sha512(expandedCredential)

        ## Issuance date and expiration date
        issuance_date = datetime.now(UTC).replace(microsecond=0)
        expiration_date = issuance_date + expirationTimedelta

        ## Prepare the issuer id and the id from the credential
        issuerDid = f"{didWeb}:{issuerId}"
        
        ## Add the information to the credential
        credentialAttributes = {
            "id": f"urn:uuid:{id}",
            "issuer": issuerDid,
            "validFrom": issuance_date.isoformat() + "Z",
            "validUntil": expiration_date.isoformat() + "Z"
        }

        credential.update(credentialAttributes)

        ## Prepare the header with the specification
        header = {
            'typ': 'vc+ld',
            'b64': False,
            'crv': 'Ed25519'
        }

        ## Prepare the content to sign
        to_sign = cryptool.encodeBase64NoPadding(json.dumps(header).encode('utf-8')) + b'.' + cryptool.encodeBase64NoPadding(json.dumps(credential).encode('utf-8'))
        signature = cryptool.encodeBase64NoPadding(private_key.sign(to_sign))


        ## Build the payload of the signature
        payload = cryptool.encodeBase64NoPadding(json.dumps({
            "exp": expiration_date.timestamp(),
            "iss": issuerDid,
            "checksum": checksum
        }).encode('utf-8'))

        ## Build the jws signature
        jws = (cryptool.encodeBase64NoPadding(json.dumps(header).encode('utf-8')) + b'.' + payload + b'.' + signature).decode()

        ## Add the information to the proof
        credential["proof"] = {
            "type": "JsonWebSignature2020",
            "proofPurpose": "assertionMethod",
            "verificationMethod": f"{issuerDid}#{methodId}",
            "created": issuance_date.isoformat() + "Z",
            "proofValue": jws
        }


        return credential

    @staticmethod
    def issueJwsVerifiableCredential(walletUrl, methodId, issuerId, expirationTimedelta, private_key, credential):
        ## Generate the DID web for the wallet url
        didWeb = cryptool.urlToDidWeb(url=walletUrl)

        ## Expand verifiable credential to check if its a valid json-ld
        try:
            expandedCredential = jsonld.expand(credential)
        except:
            raise Exception("It was not possible to expand the json-ld credential! Invalid JSON-LD!")

        ## Issuance date and expiration date
        issuance_date = datetime.now(UTC).replace(microsecond=0)
        expiration_date = issuance_date + expirationTimedelta

        ## Prepare the issuer id and the id from the credential
        issuerDid = f"{didWeb}:{issuerId}"
        id = uuid.uuid4()
        ## Add the information to the credential
        credentialAttributes = {
            "id": f"urn:uuid:{id}",
            "issuer": issuerDid,
            "validFrom": issuance_date.isoformat() + "Z",
            "validUntil": expiration_date.isoformat() + "Z"
        }

        credential.update(credentialAttributes)

        ## Prepare the header with the specification
        header = {
            'typ': 'vc+ld',
            'b64': False,
            'crv': 'Ed25519'
        }
        
        ## Prepare the content to sign
        to_sign = cryptool.encodeBase64NoPadding(json.dumps(header).encode('utf-8')) + b'.' + cryptool.encodeBase64NoPadding(json.dumps(credential).encode('utf-8'))
        decodedSignature = private_key.sign(data=to_sign)
        signature = cryptool.encodeBase64NoPadding(decodedSignature)
        

        ## Build the payload of the signature
        ## Build the jws signature
        jws = (cryptool.encodeBase64NoPadding(json.dumps(header).encode('utf-8')) + b'..' + signature).decode()

        ## Add the information to the proof
        credential["proof"] = {
            "type": "JsonWebSignature2020",
            "proofPurpose": "assertionMethod",
            "verificationMethod": f"{issuerDid}#{methodId}",
            "created": issuance_date.isoformat() + "Z",
            "jws": jws
        }


        return credential

    @staticmethod
    def verifyVerifiableCredential(credential):
        global SUPPORTED_VERIFICATION_TYPES

        if("proof" not in credential):
            raise RuntimeError("Proof is not available in the Verifiable Credential!")

        if("expirationDate" in credential):
            currentDate = datetime.now(UTC)
            expirationDate = datetime.fromisoformat(credential["expirationDate"])
            if(expirationDate is None):
                raise RuntimeError("Invalid expiration date format!")
            
            if(currentDate >= expirationDate):
                raise RuntimeError("The verifiable credential is not valid! Expiration date has passed!")

        proof = credential["proof"]
        if("type" not in proof):
            raise RuntimeError("Verification Signature Type not found in the Verifiable Credential!")
        
        verificationType = proof["type"]
        if not (verificationType in SUPPORTED_VERIFICATION_TYPES):
            raise RuntimeError("Verification Signature Type is not supported!")
        
        try:
            if(verificationType == "JsonWebSignature2020"):
                resolution = cryptool.verifyJwsProof(proof, payload=credential)
            else:
                raise RuntimeError("Verification Signature Type is not supported!")

            if(not resolution):
                raise RuntimeError(f"It was not possible to verify the signature! Verifiable Credential is not valid!")
            
        except Exception as e:
            raise RuntimeError(f"It was not possible to verify the signature!  REASON: [{e}]")


    @staticmethod
    def verifyJwsProof(proof, payload):
        if("jws" not in proof):
            raise RuntimeError("Verification Signature is not available")

        signature = proof["jws"]
        if(signature == ""):
            raise RuntimeError("Verification Signature is empty!")
        
        if("verificationMethod" not in proof):
            raise RuntimeError("Verification Method not found in the Verifiable Credential!")
        
        didMethod = proof["verificationMethod"]
        resolvedUrl = cryptool.resolveDidWeb(did_web=didMethod)
        try:
            content = HttpUtils.do_get(url=resolvedUrl, allow_redirects=True)
        except:
            raise RuntimeError(f"The content from the DID [{didMethod}] was not found in resolved URL [{resolvedUrl}]!")
        
        if(content is None):
            raise RuntimeError(f"No resposne received from resolved URL [{resolvedUrl}]!")
        
        if(content.content is None) or (content.content == ""):
            raise RuntimeError(f"No DID content received from resolved URL [{resolvedUrl}]!")

        try:
            didDocument = op.json_string_to_object(content.content)
        except:
            raise RuntimeError(f"The DID document is not a valid JSON!")
        if(didDocument is None):
            raise RuntimeError(f"The DID document its not available!")
        
        if not("verificationMethod" in didDocument):
            raise RuntimeError(f"The DID document has no verification method available!")

        publicKeysMethods = didDocument["verificationMethod"]
        publicKeyMethod = op.search_element_by_field(array=publicKeysMethods,id=didMethod, field="id")
        if (publicKeyMethod is None):
            raise RuntimeError(f"The public key method is not found in the DID document public keys list!")

        if not("type" in publicKeyMethod):
            raise RuntimeError(f"No type found in the public key method!")
        
        if(publicKeyMethod["type"] != "JsonWebKey2020"):
            raise RuntimeError(f"Public key method is not supported!")
        
        if not("publicKeyJwt" in publicKeyMethod):
            raise RuntimeError(f"No public key object found in the public key method!")
        
        publicKeyJwt = publicKeyMethod["publicKeyJwt"]
        
        key = jwk.JWK.from_json(key=op.to_json(publicKeyJwt))
        publicKeyPem = key.export_to_pem(private_key=False)
        public_key = cryptool.loadPublicKeyFromString(publicKeyPem)

        JWSignature = signature.split(".")
        header = cryptool.decodeBase64NoPadding(JWSignature[0]).decode("utf-8")
        signature = cryptool.decodeBase64NoPadding(JWSignature[2])
        credential = copy.deepcopy(payload)
        del credential["proof"]
        
        to_verify = cryptool.encodeBase64NoPadding(json.dumps(json.loads(header)).encode('utf-8')) + b'.' + cryptool.encodeBase64NoPadding(json.dumps(credential).encode('utf-8'))
        try:
            public_key.verify(signature=signature, data=to_verify)
        except InvalidSignature:
            raise RuntimeError("The credential is not verified! The signature was not able to be verified againts the data!")
        except Exception:
            raise RuntimeError("The credential is unverifiable! Something went wrong during the verification process!")
        
        return True 
        



    @staticmethod
    def signJwsVerifiableCredential(request,private_key, data):
        header = {
            'typ': 'vc+ld',
            'b64': False,
            'ald': 'HS256',
            'crv': 'Ed25519',
            "crit":["b64"]
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
    def generateEd25519PrivateKey():
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
    def publicKeyToString(private_key):
        return private_key.public_bytes(
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