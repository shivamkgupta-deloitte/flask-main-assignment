import io
import json
from urllib import response
from flask import Flask, request, jsonify, make_response, Response
import uuid
from flask_sqlalchemy import SQLAlchemy
import jwt
import datetime
import csv
from functools import wraps
from app import app, db
from app.models import Product
import requests

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route('/product/addproduct', methods = ['POST'])
def add_product():

    app.logger.info('add product')
    data = request.get_json()
    new_product = Product(name=data['name'], desc=data['desc'], category=data['category'], quantity=data['quantity'], price=data['price'], discount_id=data['discount_id'])
    db.session.add(new_product)
    db.session.commit()
    return jsonify({ 'message' : "Added Product!"}), 201

@app.route('/product/sort/price', methods = ['GET'])
def sortby_price():

    app.logger.info('sort by price')
    product = Product.query.sort_by(Product.price).all()
    response = jsonify(product)
    return response

@app.route('/product/<product_id>', methods = ['GET'])
def product_details(product_id):

    app.logger.info('product details')
    product = Product.query.filter_by(prouct_id=Product.id).first()
    response = jsonify(product)
    return response

# @app.route('/product/addtocart/<product_id>', methods = ['POST'])
# def add_to_cart(product_id):

#     app.logger.info('add to cart')
#     response = request.post('http://127.0.0.1:502/product/addtocart/' +str(product_id))
#     return response.json()

