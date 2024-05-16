from flask import Flask
from cliente_routes import cliente_app

app = Flask(__name__)
app.register_blueprint(cliente_app)

if __name__ == '__main__':
    app.run(debug = True)