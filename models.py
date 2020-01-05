from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Pais(db.Model):
    __tablename__='paises'
    id = db.Column(db.Integer, primary_key = True) 
    name = db.Column(db.String(50), unique = True, nullable = False)

    def __repr__(self):
        return '<Pais %r>' % self.name
            
    def serialize(self):
        return {
            'id':self.id,
            'name':self.name
        }


class Role(db.Model):
    __tablename__='roles'
    id = db.Column(db.Integer, primary_key = True) 
    descripcion = db.Column(db.String(50), unique = True, nullable = False)

    def __repr__(self):
        return '<Role %r>' % self.descripcion
            
    def serialize(self):
        return {
            'id':self.id,
            'descripcion':self.descripcion
        }

class Categoria(db.Model):
    __tablename__='categorias'
    id = db.Column(db.Integer, primary_key = True) 
    descripcion = db.Column(db.String(50), unique = True, nullable = False)

    def __repr__(self):
        return '<Categoria %r>' % self.descripcion
            
    def serialize(self):
        return {
            'id':self.id,
            'descripcion':self.descripcion
        }        

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(60), nullable=True)
    username = db.Column(db.String(60), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    roles_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    role = db.relationship("Role")
    
    def __repr__(self):
        return '<User %r>' % self.nombre

    def serialize(self):
        return {
            "id": self.id,
            "nombre": self.nombre,
            "username": self.username,
            "role": self.role.serialize()
        }