from app import db

class Product(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(50))
    desc = db.Column(db.String(120))
    category = db.Column(db.String(50))
    quantity = db.Column(db.Integer)
    price = db.Column(db.Integer)
    discount_id = db.Column(db.Integer)