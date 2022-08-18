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
from app.models import Order
import requests

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route('/order', methods = ['POST'])
def order_product():

    app.logger.info('order product')
    data = request.get_json()
    new_order = Order(product_id=data['product_id'], quantity=data['quantity'], payment_id=data['payment_id'], discount_id=data['discount_id'])
    db.session.add(new_order)
    db.session.commit()
    return jsonify({'Message' : 'Product Order!'}), 201
