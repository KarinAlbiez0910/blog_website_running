from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CreateRegisterForm, CreateLoginForm, CreateCommentForm
from flask_gravatar import Gravatar
from flask import abort
from functools import wraps
import smtplib
import os

my_email = 'myalbiez@gmail.com'
my_password = 'KarineProg1'
recipient = 'kalbiez@yahoo.com'


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)



##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="parent_post")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    comment_author = relationship("User", back_populates="comments")
    parent_post = relationship("BlogPost", back_populates="comments")
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))


db.create_all()

def only_admin(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return function(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = CreateRegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash_message = flash('You have already signed up with that e-mail. Log in instead')
            return redirect(url_for('login'))
        else:
            hashed_password = generate_password_hash(password=form.data.get("password"), method='pbkdf2:sha256', salt_length=8)
            registered_user = User(
                email = form.data.get("email"),
                password= hashed_password,
                name = form.data.get("name")
            )
            db.session.add(registered_user)
            db.session.commit()
            login_user(registered_user)
            return render_template('index.html', logged_in=current_user.is_authenticated)

    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['POST', 'GET'])
def login():
    form= CreateLoginForm()
    if form.validate_on_submit():
        login_password= form.password.data
        if User.query.filter_by(email=form.email.data).first():
            user = User.query.filter_by(email=form.email.data).first()
            if check_password_hash(user.password, login_password):
                login_user(user)
                return render_template('index.html', logged_in=current_user.is_authenticated)
            else:
                flash('Password incorrect. Please try again')
                return render_template("login.html", form=form, logged_in=current_user.is_authenticated)
        else:
            flash('That email does not exist. Please try again.')
            return render_template("login.html", form=form, logged_in=current_user.is_authenticated)
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CreateCommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            comment = Comment(
                text = form.body.data,
                comment_author=current_user,
                parent_post=requested_post
            )
            db.session.add(comment)
            db.session.commit()

        else:
            flash('Please be sure to log in first')
            return redirect(url_for('login'))

    return render_template('post.html',
                           post=requested_post,
                           logged_in=current_user.is_authenticated,
                           form=form)



@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact", methods=['POST', 'GET'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        message = request.form['message']
        print(name, email, phone, message)
        text = f"{name} with the email {email} and " \
               f"phone number {phone} has sent you the following message: {message}.".encode('utf-8')
        with smtplib.SMTP(host='smtp.gmail.com') as connection:
            connection.starttls()
            connection.login(password=my_password, user=my_email)
            connection.sendmail(from_addr=my_email,
                                to_addrs=recipient,
                                msg=f'Subject: New person got in contact\n\n{text}')
        return render_template('contact.html', message_sent=True)
    return render_template('contact.html', message_sent=False, logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=['POST', 'GET'])
@only_admin
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods= ['POST', 'GET'])
@only_admin
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@only_admin
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run()
