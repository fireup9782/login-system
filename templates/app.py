import pymongo

import datetime

from bson.objectid import ObjectId

from pymongo.mongo_client import MongoClient

from pymongo.server_api import ServerApi

from flask import Flask, render_template, request, redirect, url_for, flash

from passlib.hash import sha256_crypt

app = Flask('loginsystem')

app.secret_key = "123456789"

uri= "mongodb+srv://lauvacat:Ow42onZpO4fqruxj@cluster0.7fifn.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

client = pymongo.MongoClient(uri, tls=True, tlsAllowInvalidCertificates=True)
db = client.loginsystem

@app.route('/',methods =['GET','POST'])

def register():
    if request.method == 'GET':
        return render_template('index.html')
    elif request.method == 'POST':
        doc = {}
        print(request.form)
        doc['username'] = request.form["username"]
        password = request.form["password"]
        password1 = sha256_crypt.hash(password1)
        doc["password1"] = password1
            
        print(doc)
        db.users.insert_one(doc)
        print('insert', doc)
        flash('Account created successfully!')
        return redirect('/login')


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return render_template('index.html')
    elif request.method == 'POST':
        print(request.form)
        doc = {'email':request.form['email']}

        found = db.users.find_one(doc)
        print(found)
##        password = request.form["password"]
##        password1 = sha256_crypt.hash(password)

        if found is None:
            flash('The email and password you entered did not match our record. Please double check and try again.')
            return redirect('/login')
        else:
            session['user-info'] = {'firstname':found['firstname'],'lastname':found['lastname'],'email':found['email']}
            return redirect('/home')
        print(sha256_crypt.verify(password, found['password']))
        if sha256_crypt.verify(password1, found['password']):
            session['email'] = email
            return redirect('/home')
            
        else:
            print('wrong')
            flash('incorrect')
            return redirect('/')



@app.route('/home', methods = ['GET', 'POST'])
def home():
    if 'email' not in session:
        flash('You must login')
        return redirect('/')
    return render_template('home.html')

@app.route('/logout')
def logout():
        session.clear()
        flash('logout successful')
        return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
