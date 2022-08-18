import io
import json
from urllib import response
from flask import Flask, request, jsonify, make_response, Response
import uuid
from flask_sqlalchemy import SQLAlchemy
import datetime
import csv
from functools import wraps
from app import app, db
from app.models import Cart
import requests


@app.route('/cart/addtocart/<product_id>', methods = ['POST'])
def add_to_cart():
    
    app.logger.info('add to cart')
    data = request.get_json()
    new_product = Cart(prouct_id=data['product_id'], quantity=data['quantity'])
    db.session.add(new_product)
    db.session.commit()
    return jsonify({ 'message' : "Added Product!"}), 201

@app.route('/cart/removefromcart/<product_id>', methods = ['DELETE'])
def remove_from_cart(product_id):
    
    app.logger.info('remove from cart')
    cart = Cart.query.filter_by(product_id=product_id).first()
    if not cart:
        app.logger.error('Product not found in cart!')
        return jsonify({'message' : 'Product not in cart!'}), 404

    db.session.delete(cart)
    db.session.commit()

    return jsonify({'message' : 'Product removed from cart!'})
