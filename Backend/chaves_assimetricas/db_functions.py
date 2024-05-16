import pyodbc
from seg_senha import encrypt_md5

#Conexão com o Banco de dados
cnxn = pyodbc.connect('DRIVER={SQL Server};SERVER=NOT_DAVI\SQLEXPRESS;DATABASE=Teste_jwt')
cursor = cnxn.cursor()

#Criação da tabela "clientes"
cursor.execute("""
               IF NOT EXISTS (SELECT 1 FROM SYS.OBJECTS WHERE NAME = 'clientes')
                BEGIN
                    CREATE TABLE clientes(
                    id INTEGER IDENTITY(1,1) PRIMARY KEY,
                    nome VARCHAR(255) NOT NULL,
                    usuario VARCHAR(255) NOT NULL,
                    senha VARCHAR(100) NOT NULL,
                    genero VARCHAR(10),
                    data_nascimento DATE,
                    CONSTRAINT UK_usuario UNIQUE (usuario))
                END
               """)
cursor.commit()

def verifica_usuario_existente_db(usuario):
    select_usuario_existente = cursor.execute(f"SELECT usuario,senha FROM clientes WHERE usuario = '{usuario}'").fetchall()
    resposta = [tuple(row) for row in select_usuario_existente]
    if not resposta:
        return True
    return False

def insert_tabela(cliente):
    cursor.execute(f"INSERT INTO clientes VALUES('{cliente.nome}', '{cliente.usuario}', '{cliente.senha}', '{cliente.genero}', '{cliente.data_nascimento}')")
    cursor.commit()

def verifica_login_db(login, senha):
    #encripta a senha do input
    senha_encrypt = encrypt_md5(senha)
    #Busca a existência de um cliente com as credenciais descritas
    select_verificacao = cursor.execute(f"SELECT usuario,senha FROM clientes WHERE usuario = '{login}'").fetchall()
    resposta = [tuple(row) for row in select_verificacao]
    #Verifica se será um select vazio
    if not resposta:
        return 'Cliente inexistente', 401
    #Armazena em lista os resultados 
    lista_resultado = resposta[0]
    #Divide a lista em variáveis
    usuario_comparacao = lista_resultado[0]
    senha_comparacao = lista_resultado[1]
    #Verificação final
    if login == usuario_comparacao and senha_encrypt == senha_comparacao:
        return True
    return 'Acesso negado', 401