from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, ValidationError, TextField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, InputRequired

app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['SECRET_KEY'] = "secret"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
login = LoginManager(app)
login.login_view = "login"
db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(128), index=True, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    posts = db.relationship('Post', backref='author', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    body = db.Column(db.String, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_on = db.Column(db.DateTime, server_default=db.func.now())
    updated_on = db.Column(
        db.DateTime, server_default=db.func.now(), server_onupdate=db.func.now())
    user = db.relationship('User', backref='post')


class NewPost(FlaskForm):
    title = StringField("Article Title", validators=[
                        DataRequired(), Length(min=5, max=255)])
    body = TextField("Article Body", validators=[
        DataRequired(), Length(min=5)])
    submit = SubmitField("Submit")


db.create_all()

# User =======================================================
@login.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route("/")
def home():
    return render_template("layout.html")


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form['email']).first()
        if user is not None and user.check_password(request.form['password']):
            flash("Logged in successfully!", 'success')
            login_user(user)
            return redirect(url_for("profile"))
        flash('Sorry, your username or password is incorrect.', "danger")
        return redirect(url_for("login"))
    else:
        return render_template("login.html")


@app.route("/profile")
@login_required
def profile():
    posts_count = Post.query.filter_by(author_id=current_user.id).count()
    return render_template("profile.html", user=current_user, count=posts_count)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/register", methods=["POST", "GET"])
def sign_up():
    if request.method == "POST":
        check_dup = User.query.filter_by(email=request.form['email']).first()
        if check_dup is None:
            new_user = User(
                email=request.form['email'], user_name=request.form['name'])
            new_user.set_password(request.form['password'])
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for("login"))
        else:
            flash("Sign up not successful! Email already exists", "danger")
    return render_template("signup.html")

# Posts ================================================================
@app.route("/posts")
@login_required
def posts():
    posts = Post.query.filter_by(author_id=current_user.id).all()
    return render_template("posts.html", posts=posts)


@app.route("/upload", methods=["POST", "GET"])
@login_required
def upload():
    form = NewPost()
    if request.method == "POST":
        if form.validate_on_submit():
            new_post = Post(title=form.title.data,
                            body=form.body.data, author_id=current_user.id)
            db.session.add(new_post)
            db.session.commit()
            flash("Post successfully uploaded!", 'success')
            return redirect(url_for("posts"))
    return render_template("create_form.html", form=form)


@app.route("/edit/<id>", methods=["POST", "GET"])
@login_required
def edit(id):
    form = NewPost()  # Reuse form for post creation
    post = Post.query.filter_by(id=id).first()
    if request.method == "POST":
        if form.validate_on_submit():
            post.title = form.title.data
            post.body = form.body.data
            post.updated_on = datetime.now().now()
            db.session.commit()
            flash("Post successfully edited!", 'success')
            return redirect(url_for("posts"))
    return render_template("edit_form.html", form=form, post=post)


@app.route("/delete/<id>", methods=["POST", "GET"])
@login_required
def delete(id):
    post = Post.query.filter_by(id=id).first()
    db.session.delete(post)
    db.session.commit()
    flash("Post successfully deleted!", 'success')
    return redirect(url_for("posts"))


if __name__ == '__main__':
    app.run(debug=True)
