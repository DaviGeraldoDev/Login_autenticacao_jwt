from db_functions import insert_tabela, verifica_login_db, verifica_usuario_existente_db
from model_cliente import Cliente 
from seg_senha import encrypt_md5

#Implementação: Mais pra frente ao invés de args usar obj criado no front
#Perguntar p Brutus que ele manja
def checagem_campos(*args):
    lista_checagem = []
    for a in args:
        if a != '' and a != None:
            lista_checagem.append(True)
        else:
            lista_checagem.append(False)

    if all(lista_checagem):
        return True
    return False

def cadastro_cliente(nome, usuario, senha, genero, data_nascimento):
    checagem = checagem_campos(nome, usuario, senha, genero, data_nascimento)
    if checagem == True:
        verificacao = verifica_usuario_existente_db(usuario)
        if verificacao == True:
            #Hash acontece na classe, se fosse pra definir num de caracteres na senha ou tipo de caracteres
            #Faria aqui
            novo_cliente = Cliente(nome, usuario, senha, genero, data_nascimento)
            insert_tabela(novo_cliente)
            return 'Cliente cadastrado com sucesso', 200

        return 'Usuário existente',  401
    return 'Preencha todos os campos',  401

def verifica_login(login,senha):
    checagem = checagem_campos(login, senha)
    if checagem == True: 
        return verifica_login_db(login,senha)
    return 'Preencha todos os campos',  401

def verifica_usuario_existente(usuario):
    checagem = checagem_campos(usuario)
    if checagem == True: 
        resultado = verifica_usuario_existente_db(usuario)
        if resultado == True:
            return 'Nome de usuario valido', 200
        return 'Nome de usuario invalido', 401
    return 'Preencha o campo', 401