from datetime import datetime 
# first import the module
from cryptography.hazmat.primitives import serialization
import jwt
from jwt import InvalidSignatureError

def iniciandoJWT():
    data_hora_atual = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    hora = datetime.time(datetime.now()).hour
    exp = datetime.now().strftime(f'%Y-%m-%d {hora+1}:%M:%S')

    payload_data = {
        'create': data_hora_atual,
        'expe': exp
    }

    secret_key = b'de2d4dba9ca94e7cd4fc69c426449b11'

    private_key = open('Backend/chaves_assimetricas/ssh/key', 'r').read()
    key = serialization.load_ssh_private_key(private_key.encode(), password=secret_key)

    new_token = jwt.encode(
        payload=payload_data,
        key=key,
        algorithm='RS256'
    )

    return new_token

def verifica_e_decodifica_jwt(token):
    public_key = open('Backend/chaves_assimetricas/ssh/key.pub', 'r').read()
    pubKey = serialization.load_ssh_public_key(public_key.encode())

    try:
        payload_decodificado = (jwt.decode(jwt=token, key=pubKey, algorithms=['RS256']))
        return 'OK', 200
    except InvalidSignatureError as e:
        return 'Faça o Login', 401