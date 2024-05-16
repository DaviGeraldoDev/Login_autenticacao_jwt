from seg_senha import encrypt_md5 

class Cliente:
    def __init__(self, nome, usuario, senha, genero, data_nascimento):
        self._nome = nome
        self._usuario = usuario
        self._senha = encrypt_md5(senha)
        self._genero = genero
        self._data_nascimento = data_nascimento 

    @property
    def nome(self):
        return self._nome
    
    @property
    def usuario(self):
        return self._usuario

    @property
    def senha(self):
        return self._senha
    
    @property
    def genero(self):
        return self._genero

    @property
    def data_nascimento(self):
        return self._data_nascimento