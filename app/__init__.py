from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from .views import app_views

db = SQLAlchemy()

# def create_app():
#     app = Flask(__name__)
#     app.register_blueprint(app_views)
#     return app


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), unique=True, nullable=False)
    device_type = db.Column(db.String(50), nullable=True)
    
    def __repr__(self):
        return f'<Device {self.mac_address}>'

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///network.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    
    with app.app_context():
        db.create_all()

    app.register_blueprint(app_views)
    
    return app

