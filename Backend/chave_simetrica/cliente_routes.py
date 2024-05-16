from JWT import verifica_e_decodifica_jwt, iniciandoJWT
from flask_cors import CORS
from flask import Blueprint, request, render_template
from cliente_service import cadastro_cliente , verifica_login, verifica_usuario_existente

cliente_app = Blueprint('cliente_app',  __name__)

CORS(cliente_app)

@cliente_app.route('/cliente',methods=['POST'])
def criar_cliente():
    dados = request.get_json()
    resultado_cadastro = cadastro_cliente(dados['nome'], dados['usuario'],dados['senha'],dados['genero'],dados['data_nascimento'])
    return resultado_cadastro

@cliente_app.route('/cliente/usuario_existente',methods=['POST'])
def verifica_usuario():
    dados = request.get_json()
    resultado_cadastro = verifica_usuario_existente(dados['usuario'])
    return resultado_cadastro

@cliente_app.route('/cliente', methods=['GET'])
def acesso():
    jwt = request.headers.get('Token')
    retorno_jwt = verifica_e_decodifica_jwt(jwt)
    if retorno_jwt == 'OK':
        return render_template('Success.html')
    return retorno_jwt

@cliente_app.route('/cliente/login', methods=['POST'])
def verfica_login_rota():
    dados = request.get_json()
    verificacao_login = verifica_login(dados['login'], dados['senha'])
    if verificacao_login == True:
        return iniciandoJWT()
    return verificacao_login