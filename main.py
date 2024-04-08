from flask import Flask, request, render_template, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash

from pymongo import MongoClient
from pymongo.server_api import ServerApi
from pymongo.collection import Collection, ReturnDocument
from bson.objectid import ObjectId
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

uri = "mongodb+srv://uceeuno:SYX0138@elec0138.agwdphf.mongodb.net/?retryWrites=true&w=majority&appName=ELEC0138"

client = MongoClient(uri, server_api=ServerApi('1'))
db = client['ELEC0138']
users_col = db['users']
admin_col = db['admins']
posts_col = db['posts']

try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)

@app.route('/')
def home():
    return render_template('index.html')

# USER LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users_col.find_one({'username': username})
        if user and user['password'] == password:
            session['username'] = username
            return redirect(url_for('view_posts'))
        else:
            flash('Invalid username or password','error')
            return redirect(url_for('login'))
    return render_template('login.html')

# admin login
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = admin_col.find_one({'username': username})
        if user and user['password'] == password:
            session['admin'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin username or password','error')
            return redirect(url_for('admin_login'))
    return render_template('admin_login.html')

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Username and password cannot be empty.','error')
            return redirect(url_for('register'))
        user = users_col.find_one({'username': username})
        if user:
            flash('Username already exists.','error')
            return redirect(url_for('register'))

        else:
            users_col.insert_one({'username': username, 'password': password})
            flash('User registered successfully. Please login.','success')
            return redirect(url_for('login'))
    return render_template('register.html')

# post
@app.route('/post', methods=['GET', 'POST'])
def post_message():
    if 'username' not in session and 'admin' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        message = request.form['message']
        title = request.form['title']
        username = session.get('admin', 'admin') if 'admin' in session else session['username']
        if not title or not message:
            flash('Content can not be empty', 'error')
            return redirect(url_for('post_message'))
        else:
            posts_col.insert_one({'username': username, 'message': message, 'title': title})
            flash('Your post has been added successfully!','success')
            return redirect(url_for('view_posts'))
    return render_template('post_message.html')


# Comment submission
@app.route('/posts/<post_id>/comment', methods=['POST'])
def post_comment(post_id):
    if 'username' not in session and 'admin' not in session:
        flash('You need to be logged in to comment.', 'error')
        return redirect(url_for('login'))

    post_id = request.form['post_id']
    comment_content = request.form['comment']
    username = session.get('admin', 'admin') if 'admin' in session else session['username']

    if not comment_content:
        flash('Comment cannot be empty.', 'error')
        return redirect(url_for('view_posts'))


    db['comments'].insert_one({
        'post_id': post_id,
        'username': username,
        'content': comment_content
    })

    flash('Comment added successfully.', 'success')
    return redirect(url_for('view_posts'))

# view all posts
@app.route('/posts')
def view_posts():
    if 'username' not in session and 'admin' not in session:
        return redirect(url_for('login'))
    posts = list(posts_col.find())
    for post in posts:
        comments = list(db.comments.find({"post_id": str(post["_id"])}))
        post["comments"] = comments

    return render_template('view_posts.html', posts=posts)

# admin dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))
    return render_template('admin_dashboard.html')

# Log out
@app.route('/logout')
def logout():

    session.pop('username', None)
    session.pop('admin', None)
    return redirect(url_for('home'))

@app.route('/admin/users')
def admin_users():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    users = list(users_col.find())
    return render_template('admin_users.html', users=users)

@app.route('/posts/delete/<post_id>', methods=['POST'])
def delete_post(post_id):
    if 'username' not in session and 'admin' not in session:
        flash('You must be logged in to perform this action.', 'error')
        return redirect(url_for('login'))

    post = posts_col.find_one({'_id': ObjectId(post_id)})

    if post is None:
        flash('Post not found.', 'error')
        return redirect(url_for('view_posts'))

    if 'admin' in session or post['username'] == session.get('username'):
        try:
            result = posts_col.delete_one({'_id': ObjectId(post_id)})
            if result.deleted_count > 0:
                flash('Post deleted successfully.', 'success')
                return redirect(url_for('view_posts'))
            else:
                flash('An error occurred while deleting the post.', 'error')
                return redirect(url_for('view_posts'))
        except Exception as e:
            print(e)
            flash('An error occurred while deleting the post.', 'error')
    else:
        flash('You do not have permission to delete this post.', 'error')

    return redirect(url_for('view_posts'))

if __name__ == '__main__':
    app.run(debug=False)
