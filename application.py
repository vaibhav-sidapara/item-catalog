import json
import random
import string
import requests
import httplib2
from flask import make_response
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, asc
from flask import session as login_session
from oauth2client.client import FlowExchangeError
from database_setup import Base, User, Category, Item
from oauth2client.client import flow_from_clientsecrets
from flask import Flask, render_template, request, \
    redirect, jsonify, url_for, flash

app = Flask(__name__)


CLIENT_ID = json.loads(open('client_secrets.json', 'r')
                       .read())['web']['client_id']

# Connect to Database and create database session
engine = create_engine('sqlite:///item-catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Login Page View
@app.route('/login')
def show_login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# Logout Page View
@app.route('/logout')
def show_logout():
    if 'username' in login_session:
        return render_template('logout.html',
                               username=login_session['username'])
    else:
        return redirect(url_for('show_catalog'))


# Authenticate Google User
@app.route('/google-login', methods=['POST'])
def google_login():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    code = request.data

    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error'), 500))
        response.headers['Content-Type'] = 'application/json'
        return response

    google_id = credentials.id_token['sub']

    if result['user_id'] != google_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify Access Token
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('google_id')

    if stored_access_token is not None and google_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store Access Token In Session
    login_session['access_token'] = credentials.access_token
    login_session['google_id'] = google_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {
        'access_token': credentials.access_token,
        'alt': 'json'
    }

    answer = requests.get(userinfo_url, params=params)
    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = get_user_id(login_session['email'])

    if user_id is None:
        user_id = create_user(login_session)

    login_session['user_id'] = user_id

    return render_template('login_confirmation.html',
                           login_session=login_session)


# Logout Google User
@app.route('/google-logout')
def google_logout():
    access_token = login_session.get('access_token')

    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    username = login_session['username']

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % \
          login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    print 'result is '
    print result

    if result['status'] == '200':
        # Remove Access Token From Session
        del login_session['access_token']
        del login_session['google_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(
            json.dumps('%s successfully logged out.' % username), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Retrieve UserID From Email
def get_user_id(email):
    user = session.query(User).filter_by(email=email).one()
    if user:
        return user.id
    else:
        return None


# Retrieve User Information From UserID
def get_user_info(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# Create New User Account
def create_user(login_session):
    new_user = User(name=login_session['username'],
                    email=login_session['email'],
                    picture=login_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# Catalog View
@app.route('/')
@app.route('/catalog')
def show_catalog():
    category_id = 1
    categories = session.query(Category).order_by(asc(Category.name)).all()
    items = session.query(Item).filter_by(category_id=category_id).all()

    template = 'catalog.html'

    if 'username' not in login_session:
        template = 'public_catalog.html'

    return render_template(template,
                           category_id=category_id,
                           categories=categories,
                           items=items,
                           login_session=login_session)


# Category View
@app.route('/category/<int:category_id>', methods=['GET', 'POST'])
def show_category(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    template = 'category.html'

    if 'username' not in login_session:
        template = 'public_category.html'

    return render_template(template,
                           category=category,
                           items=items,
                           login_session=login_session)


# Add Category View
@app.route('/category/add', methods=['GET', 'POST'])
def add_category():
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
        if request.form['name']:
            category = Category(name=request.form['name'],
                                user_id=login_session['user_id'])
            session.add(category)
            session.commit()
            return redirect(url_for('show_catalog'))
        else:
            flash('Category name is required.')
            return render_template('add_category.html',
                                   login_session=login_session)
    else:
        return render_template('add_category.html',
                               login_session=login_session)


# Edit Category View
@app.route('/category/<int:category_id>/edit', methods=['POST', 'GET'])
def edit_category(category_id):
    if 'username' not in login_session:
        return redirect('/login')

    category = session.query(Category).filter_by(id=category_id).one()

    if login_session['user_id'] == category.user_id:
        if request.method == 'POST':
            if request.form['name']:
                category.name = request.form['name']
                session.add(category)
                session.commit()
                return redirect(url_for('show_catalog'))
            else:
                flash('Category name is required.')
                return render_template('edit_category.html',
                                       category=category,
                                       login_session=login_session)
        else:
            return render_template('edit_category.html',
                                   category=category,
                                   login_session=login_session)
    else:
        # Redirect user to category page
        flash('You can only edit categories created by you.')
        items = session.query(Item).filter_by(category_id=category_id).all()
        return render_template('category.html',
                               category=category,
                               items=items,
                               login_session=login_session)


# Delete Category View
@app.route('/category/<int:category_id>/delete', methods=['POST', 'GET'])
def delete_category(category_id):
    if 'username' not in login_session:
        return redirect('/login')

    category = session.query(Category).filter_by(id=category_id).one()

    if login_session['user_id'] == category.user_id:
        if request.method == 'POST':
            session.delete(category)
            session.commit()
            return redirect(url_for('show_catalog'))
        else:
            return render_template('delete_category.html',
                                   category=category,
                                   login_session=login_session)
    else:
        # Redirect user to category page
        flash('You can only delete categories created by you.')
        items = session.query(Item).filter_by(category_id=category_id).all()
        return render_template('category.html',
                               category=category,
                               items=items,
                               login_session=login_session)


# Item View
@app.route('/category/<int:category_id>/item/<int:item_id>',
           methods=['POST', 'GET'])
def show_item(category_id, item_id):
    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(Item).filter_by(id=item_id).one()

    template = 'item.html'

    if 'username' not in login_session:
        template = 'public_item.html'

    return render_template(template,
                           category=category,
                           item=item,
                           login_session=login_session)


# Add Item View
@app.route('/category/<int:category_id>/item/add', methods=['POST', 'GET'])
def add_item(category_id):
    if 'username' not in login_session:
        return redirect('/login')

    category = session.query(Category).filter_by(id=category_id).one()

    if login_session['user_id'] == category.user_id:
        if request.method == 'POST':
            if request.form['name']:
                item = Item(
                    name=request.form['name'],
                    description=request.form['description'],
                    long_description=request.form['long_description'],
                    user_id=login_session['user_id'],
                    category_id=category_id
                    )
                session.add(item)
                session.commit()
                return redirect(url_for('show_category',
                                        category_id=category_id))
            else:
                flash('Item name is required.')
                return redirect(url_for('add_item', category_id=category_id))
        else:
            return render_template('add_item.html',
                                   category=category,
                                   login_session=login_session)
    else:
        # Redirect user to category page
        flash('You can only add items to categories created by you.')
        return render_template('category.html',
                               category=category,
                               login_session=login_session)


# Edit Item View
@app.route('/category/<int:category_id>/item/<int:item_id>/edit',
           methods=['POST', 'GET'])
def edit_item(category_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')

    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(Item).filter_by(id=item_id).one()

    if login_session['user_id'] == item.user_id:
        if request.method == 'POST':
            if request.form['name']:
                item.name = request.form['name']
                item.description = request.form['description']
                item.long_description = request.form['long_description']
                session.add(item)
                session.commit()
                return redirect(url_for('show_item',
                                        category_id=category_id,
                                        item_id=item_id))
            else:
                flash('Item name is required.')
                return render_template('edit_item.html',
                                       category=category,
                                       item=item,
                                       login_session=login_session)
        else:
            return render_template('edit_item.html',
                                   category=category,
                                   item=item,
                                   login_session=login_session)
    else:
        # Redirect user to item detail page
        flash('You can only edit items created by you.')
        return render_template('item.html',
                               category=category,
                               item=item,
                               login_session=login_session)


# Delete Item View
@app.route('/category/<int:category_id>/item/<int:item_id>/delete',
           methods=['POST', 'GET'])
def delete_item(category_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')

    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(Item).filter_by(id=item_id).one()

    if login_session['user_id'] == item.user_id:
        if request.method == 'POST':
            session.delete(item)
            session.commit()
            return redirect(url_for('show_category',
                                    category_id=category_id))
        else:
            return render_template('delete_item.html',
                                   category=category,
                                   item=item,
                                   login_session=login_session)
    else:
        # Redirect user to item detail page
        flash('You can only delete items created by you.')
        return render_template('item.html',
                               category=category,
                               item=item,
                               login_session=login_session)


# JSON API Endpoint - All Categories
@app.route('/categories/JSON')
def categories_json():
    categories = session.query(Category).all()
    return jsonify(categories=[c.serialize for c in categories])


# JSON API Endpoint - Single Category
@app.route('/category/<int:category_id>/JSON')
def category_json(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    return jsonify(category=category.serialize)


# JSON API Endpoint - All Items
@app.route('/category/<int:category_id>/items/JSON')
def items_json(category_id):
    items = session.query(Item).filter_by(category_id=category_id).all()
    return jsonify(items=[i.serialize for i in items])


# JSON API Endpoint - Single Item
@app.route('/category/<int:category_id>/items/<int:item_id>/JSON')
def category_item_json(category_id, item_id):
    item = session.query(Item).filter_by(
        category_id=category_id).filter_by(id=item_id).one()
    return jsonify(item=item.serialize)


# JSON API Endpoint - Item Attributes
@app.route('/item/<int:item_id>/JSON')
def item_json(item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(item=item.serialize)


# Custom 404 View
@app.errorhandler(404)
def page_not_found():
    return render_template('404.html', login_session=login_session), 404


if __name__ == '__main__':
    app.secret_key = 'A947F8C8C1AFAF778AE8A1DEA1838'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
