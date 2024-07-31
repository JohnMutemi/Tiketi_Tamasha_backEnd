from flask import Flask, render_template, request, redirect, url_for
from init import app, db, login_manager
from models import Org
from flask_login import UserMixin

@login_manager.user_loader
def load_user(org_id):
    return Org.query.get(int(org_id))

@app.route('/add_org', methods=['GET', 'POST'])
def add_org():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        occasion = request.form['occasion']
        location = request.form['location']
        price = request.form['price']
        address = request.form['address']
        contact = request.form['contact']
        requirement = request.form['requirement']
        image_file = request.form['image_file']
        details = request.form['details']
        accomodation = request.form['accomodation']
        special = request.form['special']
        
        new_org = Org(
            name=name,
            email=email,
            password=password,
            occasion=occasion,
            location=location,
            price=price,
            address=address,
            contact=contact,
            requirement=requirement,
            image_file=image_file,
            details=details,
            accomodation=accomodation,
            special=special
        )
        
        db.session.add(new_org)
        db.session.commit()
        return redirect(url_for('index'))
    
    return render_template('add_org.html')

@app.route('/')
def index():
    return "Home Page"

if __name__ == '__main__':
    app.run(debug=True)
