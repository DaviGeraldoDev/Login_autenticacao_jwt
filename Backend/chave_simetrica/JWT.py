import hmac
import hashlib
import base64
import json 
from datetime import datetime 

secret_key = '52d3f853c19f8b63c0918c126422aa2d99b1aef33ec63d41dea4fadf19406e54'

def create_jwt(payload):
    payload = json.dumps(payload).encode()
    header = json.dumps({
        'typ': 'JWT',
        'alg': 'HS256'
    }).encode()
    b64_header = base64.urlsafe_b64encode(header).decode()
    b64_payload = base64.urlsafe_b64encode(payload).decode()
    signature = hmac.new(
        key=secret_key.encode(),
        msg=f'{b64_header}.{b64_payload}'.encode(),
        digestmod=hashlib.sha256
    ).digest()
    jwt = f'{b64_header}.{b64_payload}.{base64.urlsafe_b64encode(signature).decode()}'
    return jwt

def verifica_e_decodifica_jwt(jwt):
    b64_header, b64_payload, b64_signature = str(jwt).split('.')
    b64_signature_checker = base64.urlsafe_b64encode(
        hmac.new(
            key=secret_key.encode(),
            msg=f'{b64_header}.{b64_payload}'.encode(),
            digestmod=hashlib.sha256
        ).digest()
    ).decode()

    payload = json.loads(base64.urlsafe_b64decode(b64_payload))
    date_compare_exp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if payload.get('exp') and payload['exp'] < date_compare_exp:
        return 'Token expirado', 401

    if b64_signature_checker != b64_signature:
        return 'Assinatura inválida', 401
    
    return 'OK'   

def iniciandoJWT():
    data_hora_atual = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    hora = datetime.time(datetime.now()).hour
    exp = datetime.now().strftime(f'%Y-%m-%d {hora+1}:%M:%S')

    payload = {
        'create': data_hora_atual,
        'exp': exp
    }

    token_jwt = create_jwt(payload)
    return token_jwt