import hashlib

def encrypt_md5(senha):
    senha_criptografada = hashlib.md5(senha.encode()).hexdigest()
    return senha_criptografada