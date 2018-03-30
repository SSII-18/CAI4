from time import time
from random import _urandom
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import camellia
from CryptoPlus.Cipher import python_Serpent
from Crypto import Random
from Crypto.PublicKey import RSA

def generate_random_files():
    result = []
    for longitud in (100, 500, 1000, 1500):
        for i in range(10):
            result.append(_urandom(longitud*1024))
    return result
            
def test():
    files = generate_random_files()
    algorithms = {'AES' : test_AES_128_GCM ,'CAMELLIA' : test_camellia_256_CBC , \
                  'SERPENT' : test_serpent_128_CBC ,'RSA' : test_RSA_2048_CBC}
    content = ''
    j = 0
    for i in range(4):
        content = '----------   ' + algorithms.keys()[i] + '   ----------\r\n\r\n\r\n'
        for file in files:
            j = j+1
            print('File ' + str(j))
            tiempo_cifrado, tiempo_descifrado, incremento_espacial = algorithms[algorithms.keys()[i]](file)
            content = content +  '----------\r\n' + \
            'Numero de bytes : ' + str(len(file)) + \
            'Tiempo de cifrado : ' + str(tiempo_cifrado*1000) + '\r\n' + \
            'Tiempo de descifrado : ' + str(tiempo_descifrado*1000) + '\r\n' + \
            'Incremento espacial : ' + str(incremento_espacial) + '\r\n\r\n'
        content = content + '\r\n'
    with open('results.txt', 'w') as file:
        file.write(content)
        file.close()
    
    
def test_AES_128_GCM(datos):
    tiempo_comienzo = time()
    clave = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(clave)
    nonce = _urandom(12)
    ct = aesgcm.encrypt(nonce, datos, None)
    tiempo_cifrado = time() - tiempo_comienzo 
    aesgcm.decrypt(nonce, ct, None)
    tiempo_descifrado = time() - tiempo_comienzo - tiempo_cifrado
    incremento_espacial = len(ct) - len(datos)
    return tiempo_cifrado, tiempo_descifrado, incremento_espacial
    
def test_camellia_256_CBC(datos):
    clave = _urandom(16)
    init_vector = _urandom(16)
    c1 = camellia.CamelliaCipher(key=clave, IV=init_vector, mode=camellia.MODE_CBC)
    tiempo_comienzo_cifrado = time()
    encrypted = c1.encrypt(datos)
    tiempo_cifrado = time() - tiempo_comienzo_cifrado 
    c2 = camellia.CamelliaCipher(key=clave, IV=init_vector, mode=camellia.MODE_CBC)
    tiempo_comienzo_descifrado = time()
    c2.decrypt(encrypted)    
    tiempo_descifrado = time() - tiempo_comienzo_descifrado
    incremento_espacial = len(encrypted) - len(datos)
    return tiempo_cifrado, tiempo_descifrado, incremento_espacial

def test_serpent_128_CBC(datos):
    key = _urandom(16)
    iv = Random.new().read(16)
    cipher = python_Serpent.new(key, python_Serpent.MODE_CBC, iv)
    tiempo_comienzo_cifrado = time()
    enc_datos = cipher.encrypt(datos)
    tiempo_cifrado = time() - tiempo_comienzo_cifrado
    msg = iv + enc_datos
    tiempo_comienzo_descifrado = time()
    cipher.decrypt(msg)
    tiempo_descifrado = time() - tiempo_comienzo_descifrado
    incremento_espacial = len(enc_datos) - len(datos)
    return tiempo_cifrado, tiempo_descifrado, incremento_espacial

def test_RSA_2048_CBC(datos):
    key = RSA.generate(2048)
    binPrivKey = key.exportKey('DER')
    binPubKey =  key.publickey().exportKey('DER')
    privKeyObj = RSA.importKey(binPrivKey)
    pubKeyObj =  RSA.importKey(binPubKey)
    tiempo_comienzo_cifrado = time()
    emsg = pubKeyObj.encrypt(datos, 'x')[0]
    tiempo_cifrado = time() - tiempo_comienzo_cifrado
    tiempo_comienzo_descifrado = time()
    dmsg = privKeyObj.decrypt(emsg)
    tiempo_descifrado = time() - tiempo_comienzo_descifrado
    incremento_espacial = len(emsg) - len(datos)
    return tiempo_cifrado, tiempo_descifrado, incremento_espacial

test()