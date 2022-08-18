from app import db

class Order(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    product_id = db.Column(db.Integer)
    quantity = db.Column(db.Integer)
    payment_id = db.Column(db.Integer, unique = True)
    discount_id = db.Column(db.Integer)