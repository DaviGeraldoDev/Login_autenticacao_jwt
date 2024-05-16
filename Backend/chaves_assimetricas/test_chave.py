# Primeiro gere as chaves usando o OpenSSH:
# Mkdir .ssh / cd .ssh
# ssh-keygen -t rsa
# pip install -r requirements.txt

from datetime import datetime 

# first import the module
from cryptography.hazmat.primitives import serialization

import jwt
from jwt import InvalidSignatureError

data_hora_atual = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
hora = datetime.time(datetime.now()).hour
exp = datetime.now().strftime(f'%Y-%m-%d {hora+1}:%M:%S')

payload_data = {
    'create': data_hora_atual,
    'expe': exp
}

public_key = open('Back/ssh/test.pub', 'r').read()
pubKey = serialization.load_ssh_public_key(public_key.encode())

sexo = 'sexo'
sexo_key = sexo.encode('utf-8')

private_key = open('Back/ssh/test', 'r').read()
key = serialization.load_ssh_private_key(private_key.encode(), password=sexo_key)

new_token = jwt.encode(
    payload=payload_data,
    key=key,
    algorithm='RS256'
)

print(new_token)

# Falsificando o token: 

fake_token = new_token.replace('XB','XB')

try:
    payload_decodificado = (jwt.decode(jwt=fake_token, key=pubKey, algorithms=['RS256']))
    print(payload_decodificado)
except InvalidSignatureError as e:
    print(e)
