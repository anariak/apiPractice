from flask import Flask, render_template, request, jsonify
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, create_refresh_token,
    get_jwt_identity, jwt_refresh_token_required
)
from models import db, Pais, Categoria, Role, User
from config import DevelopmentConfig

app = Flask(__name__)
app.config.from_object(DevelopmentConfig)
db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)
manager = Manager(app)
manager.add_command('db', MigrateCommand)
CORS(app)


@app.route('/')
def home():
    return render_template('index.html', name="home")

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username:
        return jsonify({"msg": "se requiere username"}), 400
    if not password:
        return jsonify({"msg": "se requiere password"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"msg":"Username not found"}), 400
    else:
        if bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=username)
            data = {
                "access_token": access_token,
                "user": user.serialize(),
                "expire_at": expires.total_seconds() * 1000,
                "user": user.serialize()
            }
            return jsonify(data), 200
        else:
            return jsonify({"msg":"Username and Password are incorrect"}), 401

@app.route('refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    current_user = get_jwt_identity()
    new_token = create_access_token(identity=current_user, fresh=False)
    ret = {'access_token': new_token}
    return jsonify(ret), 200

    

@app.route('/register', methods=['POST'])
def register():
    pass


@app.route('/paises', methods=['GET', 'POST'])
@app.route('/paises/<int:id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required
def paises(id=None):
    if request.method == 'GET':
        if id is not None:
            pais = Pais.query.get(id)
            if pais:
                return jsonify(pais.serialize()), 200
            else:
                return jsonify({"error": "Not found"}), 404
        else:
            paises = Pais.query.all()
            paises = list(map(lambda pais: pais.serialize(), paises))
            return jsonify(paises), 200

    if request.method == 'POST':

        if not request.json.get('nombre'):
            return jsonify({"nombre": "es requerido"}), 422

        data = request.get_json()
        pais = Pais.query.filter_by(name=data['nombre'].upper()).first()
        print(pais)
        if pais:
            return jsonify({"pais": data['nombre'].upper() + " ya existe"}), 200
        else:
            pais = Pais()
            pais.name = data['nombre'].upper()
            db.session.add(pais)
            db.session.commit()

        return jsonify(pais.serialize()), 201

    if request.method == 'PUT':

        data = request.get_json()
        if not request.json.get('nombre'):
            return jsonify({"nombre": "es requerido"}), 422

        pais = Pais.query.get(id)

        if not pais:
            return jsonify({"error": "not found"}), 404
        else:
            pais = Pais.query.filter_by(name=data['nombre'].upper()).first()
            if pais:
                return jsonify({"pais": data['nombre'].upper() + " ya existe"}), 200
            else:
                pais = Pais.query.get(id)
                pais.name = data['nombre'].upper()
                db.session.commit()

                return jsonify(pais.serialize()), 201

    if request.method == 'DELETE':

        pais = Pais.query.get(id)
        if not pais:
            return jsonify({"error": "not found"}), 404
        else:
            db.session.delete(pais)
            db.session.commit()
            return jsonify({"message": "delete"}), 200


@app.route('/categorias', methods=['GET', 'POST'])
@app.route('/categorias/<int:id>', methods=['GET', 'PUT', 'DELETE'])
def categorias(id=None):
    if request.method == 'GET':
        if id is not None:
            categoria = Categoria.query.get(id)
            if categoria:
                return jsonify(categoria.serialize()), 200
            else:
                return jsonify({"error": "Not found"}), 404
        else:
            categorias = Categoria.query.all()
            categorias = list(
                map(lambda categoria: categoria.serialize(), categorias))
            return jsonify(categorias), 200

    if request.method == 'POST':

        if not request.json.get('nombre'):
            return jsonify({"nombre": "es requerido"}), 422

        data = request.get_json()
        categoria = Categoria.query.filter_by(name=data['nombre'].upper()).first()
        print(categoria)
        if categoria:
            return jsonify({"categoria": data['nombre'].upper() + " ya existe"}), 200
        else:
            categoria = Categoria()
            categoria.name = data['nombre'].upper()
            db.session.add(categoria)
            db.session.commit()

        return jsonify(categoria.serialize()), 201

    if request.method == 'PUT':

        data = request.get_json()
        if not request.json.get('descripcion'):
            return jsonify({"descripcion": "es requerido"}), 422

        categoria = Categoria.query.get(id)

        if not categoria:
            return jsonify({"error": "not found"}), 404
        else:
            categoria = Categoria.query.filter_by(descripcion=data['descripcion'].upper()).first()
            if categoria:
                return jsonify({"categoria": data['descripcion'].upper() + " ya existe"}), 200
            else:
                categoria = Categoria.query.get(id)
                categoria.descripcion = data['descripcion'].upper()
                db.session.commit()

                return jsonify(categoria.serialize()), 201

    if request.method == 'DELETE':

        categoria = Categoria.query.get(id)
        if not categoria:
            return jsonify({"error": "not found"}), 404
        else:
            db.session.delete(pais)
            db.session.commit()
            return jsonify({"message": "delete"}), 200

@app.route('/roles', methods=['GET', 'POST'])
@app.route('/roles/<int:id>', methods=['GET', 'PUT', 'DELETE'])
def roles(id=None):
    if request.method == 'GET':
        if id is not None:
            roles = Role.query.get(id)
            if roles:
                return jsonify(roles.serialize()), 200
            else:
                return jsonify({"error": "Not found"}), 404
        else:
            roles = Role.query.all()
            roles = list(
                map(lambda categoria: roles.serialize(), roles))
            return jsonify(roles), 200

    if request.method == 'POST':

        if not request.json.get('descripcion'):
            return jsonify({"descripcion": "es requerido"}), 422

        data = request.get_json()
        role = Role.query.filter_by(descripcion=data['descripcion'].upper()).first()
        print(role)
        if role:
            return jsonify({"role": data['descripcion'].upper() + " ya existe"}), 200
        else:
            role = Role()
            role.descripcion = data['descripcion'].upper()
            db.session.add(role)
            db.session.commit()

        return jsonify(role.serialize()), 201

    if request.method == 'PUT':

        data = request.get_json()
        if not request.json.get('descripcion'):
            return jsonify({"descripcion": "es requerido"}), 422

        role = role.query.get(id)

        if not role:
            return jsonify({"error": "not found"}), 404
        else:
            role = Categoria.query.filter_by(
                descripcion=data['descripcion'].upper()).first()
            if role:
                return jsonify({"role": data['descripcion'].upper() + " ya existe"}), 200
            else:
                role = Role.query.get(id)
                role.descripcion = data['descripcion'].upper()
                db.session.commit()

                return jsonify(role.serialize()), 201

    if request.method == 'DELETE':

        role = Role.query.get(id)
        if not roles:
            return jsonify({"error": "not found"}), 404
        else:
            db.session.delete(roles)
            db.session.commit()
            return jsonify({"message": "delete"}), 200


@app.route('/users', methods=['GET', 'POST'])
@app.route('/users/<int:id>', methods=['GET', 'PUT', 'DELETE'])
def usuarios(id=None):
    if request.method == 'GET':
        if id is not None:
            user = User.query.get(id)
            if user:
                return jsonify(user.serialize()), 200
            else:
                return jsonify({"error": "not Found"}), 400
        else:
            users = User.query.all()
            users = list(map(lambda user: user.serialize(), users))
            return jsonify(users), 200

    if request.method == 'POST':
        data = request.get_json()
        user = User()
        user.nombre = data['nombre']
        user.username = data['username']
        pw_hash = bcrypt.generate_password_hash(data['password'])
        user.password = pw_hash
        user.roles_id = data['roles_id']

        db.session.add(user)
        db.session.commit()

        return jsonify(user.serialize()), 201

    if request.method == 'PUT':
        pass
    if request.method == 'DELETE':
        pass

if __name__ == '__main__':
    manager.run()
