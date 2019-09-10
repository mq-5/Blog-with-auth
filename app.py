from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, ValidationError, TextField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, InputRequired
from wtforms.widgets import TextArea


app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['SECRET_KEY'] = "secret"
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

POSTGRES = {
    'user': 'quyen',
    'pw': '123',
    'db': 'blog',
    'host': 'localhost',
    'port': 5432,
}
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:%(pw)s@%(host)s:\
%(port)s/%(db)s' % POSTGRES

login = LoginManager(app)
login.login_view = "login"
db = SQLAlchemy(app)

migrate = Migrate(app, db)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String, nullable=False)
    email = db.Column(db.String(128), index=True, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    comments = db.relationship('Comment', backref='author', lazy='dynamic')
    upvotes = db.relationship("UpVote", backref="user", lazy="dynamic")
    downvotes = db.relationship("DownVote", backref="user", lazy="dynamic")
    flags = db.relationship("Flags", backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_to_admin(self):
        self.is_admin = True

    def has_upvote(self, post):
        return UpVote.query.filter_by(post_id=post.id, author_id=self.id).first() is not None

    def has_downvote(self, post):
        return DownVote.query.filter_by(post_id=post.id, author_id=self.id).first() is not None

    def has_flag(self, post):
        return Flags.query.filter_by(post_id=post.id, user_id=self.id).first() is not None


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    body = db.Column(db.String, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_on = db.Column(db.DateTime, server_default=db.func.now())
    updated_on = db.Column(
        db.DateTime, server_default=db.func.now(), server_onupdate=db.func.now())
    views = db.Column(db.Integer, default=0)
    comments = db.relationship("Comment", backref="post", lazy="dynamic")
    upvotes = db.relationship("UpVote", backref="post", lazy="dynamic")
    downvotes = db.relationship("DownVote", backref="post", lazy="dynamic")
    flags = db.relationship("Flags", backref='post', lazy=True)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(255), nullable=False)
    created_on = db.Column(db.DateTime, server_default=db.func.now())
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)


class UpVote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)


class DownVote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)


class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey(
        'user.id'), nullable=False)
    follower_id = db.Column(db.Integer, db.ForeignKey(
        'user.id'), nullable=False)
    followed = db.relationship("User", foreign_keys=[
                               followed_id], backref='followed')
    follower = db.relationship("User", foreign_keys=[
                               follower_id], backref='follower')


class Flags(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


db.create_all()

# Forms ===========================================================


class NewPost(FlaskForm):
    title = StringField("Article Title", validators=[
                        DataRequired(), Length(min=5, max=50, message="Title must be 5-50 characters long")])
    body = TextField("Article Body", validators=[
        DataRequired(), Length(min=5, message="Body must be at least 5 characters")], widget=TextArea())
    submit = SubmitField("Submit")


class Login(FlaskForm):
    email = StringField("Email", validators=[Email(
        message="Please enter a valid email!"), DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class SignUp(FlaskForm):
    email = StringField("Email", validators=[
                        DataRequired(), Email(message='Please enter a valid email')])
    username = StringField("User Name", validators=[DataRequired(), Length(
        max=25, min=3, message='User name must be 3-23 characters long')])
    password = PasswordField("Password", validators=[DataRequired(), Length(
        min=3, message="Password must be at least 3 characters")])
    cf_password = PasswordField(
        "Re-enter Password", validators=[DataRequired(), EqualTo("password", message="Password not matching")])
    submit = SubmitField("Sign Up")

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError("Your email has been registered")

    def validate_username(self, field):
        if User.query.filter_by(user_name=field.data).first():
            raise ValidationError("Your username has been registered")


class NewComment(FlaskForm):
    body = StringField("Your comment here...", validators=[DataRequired(message="Data required"), Length(
        max=255, message="Maximum 255 characters")], widget=TextArea())
    submit = SubmitField("Comment")

# User =======================================================
@login.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route("/")
def home():
    return render_template("layout.html")


@app.route("/top-bloggers")
def top_bloggers():
    # import code
    # code.interact(local=dict(globals(), **locals()))
    populars = sorted(User.query.all(),
                      key=lambda x: x.upvotes.count(), reverse=True)[:3]
    posters = sorted(User.query.all(),
                     key=lambda x: x.posts.count(), reverse=True)[:3]
    commenters = sorted(User.query.all(),
                        key=lambda x: x.comments.count(), reverse=True)[:3]
    return render_template('top_bloggers.html', populars=populars,
                           posters=posters, commenters=commenters)


@app.route("/list/<criteria>")
@login_required
def lst(criteria):
    if criteria == 'follower':
        follows = Follow.query.with_entities(
            Follow.follower_id).filter_by(followed=current_user).all()
    elif criteria == 'following':
        follows = Follow.query.with_entities(
            Follow.followed_id).filter_by(follower=current_user).all()
    users = [User.query.filter_by(id=follow[0]).first() for follow in follows]
    print(users)
    return render_template("list_people.html", users=users, criteria=criteria)


@app.route("/login", methods=["POST", "GET"])
def login():
    form = Login()
    if request.method == "POST":
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user and user.check_password(form.password.data):
                login_user(user)
                flash("Logged in successfully!", 'success')
                return redirect(url_for("posts"))
            flash("Email or password is not correct", "danger")
        for field_name, errors in form.errors.items():
            flash(errors[0])
        return redirect(url_for("login"))
    else:
        return render_template("login.html", form=form)


@app.route("/profile/<id>")
@login_required
def profile(id):
    user = User.query.filter_by(id=id).first()
    posts_count = Post.query.filter_by(author_id=id).count()
    followers = Follow.query.filter_by(followed_id=id).count()
    followings = Follow.query.filter_by(follower_id=id).count()
    is_followed = Follow.query.filter_by(
        followed_id=id, follower_id=current_user.id).first()
    return render_template("profile.html", user=user, followers=followers,
                           followings=followings, is_followed=is_followed)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/register", methods=["POST", "GET"])
def sign_up():
    form = SignUp()
    if request.method == "POST":
        if form.validate_on_submit():
            new_user = User(user_name=form.username.data,
                            email=form.email.data)
            new_user.set_password(form.password.data)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for("login"))
        else:
            for field_name, errors in form.errors.items():
                flash(errors[0], 'warning')
    default = {'email': 'Enter email', 'name': 'Enter user name'}
    return render_template("signup.html", form=form, default=default)


@app.route('/edit-profile', methods=['POST', 'GET'])
@login_required
def edit_profile():
    form = SignUp()
    if request.method == 'POST':
        if form.validate_on_submit():
            current_user.email = form.email.data
            current_user.user_name = form.username.data
            current_user.set_password(form.password.data)
            db.session.add(current_user)
            db.session.commit()
            return redirect(url_for("login"))
        else:
            for field_name, errors in form.errors.items():
                flash(errors[0], 'warning')
    default = {'email': current_user.email, 'name': current_user.user_name}
    return render_template("signup.html", form=form, default=default)


# Posts ================================================================
@app.route("/posts")
def posts():
    posts = sorted(Post.query.all(), key=lambda x: x.updated_on, reverse=True)
    return render_template("posts.html", posts=posts, header="All Posts")


@app.route("/user/<id>/posts")
def user_posts(id):
    user = User.query.filter_by(id=id).first()
    posts = Post.query.filter(Post.author_id == id).all()
    return render_template("posts.html", posts=posts, header=f"{user.user_name}'s Posts")


@app.route("/user/news-feed")
@login_required
def news_feed():
    # followings = [follow.followed_id for follow in Follow.query.filter_by(
    #     follower_id=current_user.id).all()]
    followings = Follow.query.with_entities(Follow.followed_id).filter_by(
        follower_id=current_user.id).all()
    posts = [post for post in Post.query.all() if (post.author_id,)
             in followings]
    return render_template("posts.html", posts=posts, header="News Feed", Post=Post)


@app.route('/posts/<id>', methods=['POST', "GET"])
def post(id):
    post = Post.query.filter_by(id=id).first()
    if post:
        post.views += 1
        db.session.commit()
        form = NewComment()
        if request.method == "POST":
            if current_user.is_authenticated and form.validate_on_submit():
                new_comment = Comment(body=form.body.data,
                                      created_on=datetime.now())
                current_user.comments.append(new_comment)
                post.comments.append(new_comment)
                db.session.add(new_comment)
                db.session.commit()
            else:
                flash("You must sign in to comment")
                for field_name, errors in form.errors.items():
                    flash(errors[0])
            return redirect(url_for('post', id=id))
        return render_template('single_post.html', post=post, comment_form=form,
                               comments=post.comments.all())
    return redirect(url_for('post', id=id))


@app.route('/posts/flagged')
@login_required
def flagged():
    if current_user.is_admin:
        posts = sorted(Post.query.filter(Post.flags).all(),
                       key=lambda x: len(x.flags), reverse=True)
        return render_template("posts.html", posts=posts, header="Flagged Posts")
    else:
        flash("You are not authorized", 'danger')
        return redirect(url_for('posts'))

# Actions ====================================================================
@app.route("/upload", methods=["POST", "GET"])
@login_required
def upload():
    form = NewPost()
    if request.method == "POST":
        if form.validate_on_submit():
            new_post = Post(title=form.title.data,
                            body=form.body.data)
            current_user.posts.append(new_post)
            db.session.add(new_post)
            db.session.commit()
            flash("Post successfully uploaded!")
            return redirect(url_for("posts"))
    return render_template("new_post.html", form=form)


@app.route('/posts/<id>/like', methods=['POST', 'GET'])
@login_required
def like(id):
    ref = request.args.get('ref')
    try:
        post = Post.query.filter_by(id=id).one()
        if not current_user.has_upvote(post):
            upvote = UpVote(post_id=id)
            current_user.upvotes.append(upvote)
            db.session.add(upvote)
            if current_user.has_downvote(post):
                db.session.delete(DownVote.query.filter_by(
                    post_id=post.id, author_id=current_user.id).first())
        else:
            db.session.delete(UpVote.query.filter_by(
                post_id=id, author_id=current_user.id).first())
        db.session.commit()
    except:
        flash("Post not found", 'danger')
    return redirect(ref)


@app.route('/posts/<id>/dislike', methods=['POST', 'GET'])
@login_required
def dislike(id):
    ref = request.args.get('ref')
    try:
        post = Post.query.filter_by(id=id).one()
        if not current_user.has_downvote(post):
            downvote = DownVote(post_id=id)
            current_user.downvotes.append(downvote)
            db.session.add(downvote)
            if current_user.has_upvote(post):
                db.session.delete(UpVote.query.filter_by(
                    post_id=id, author_id=current_user.id).first())
        else:
            db.session.delete(DownVote.query.filter_by(
                post_id=post.id, author_id=current_user.id).first())
        db.session.commit()
    except:
        flash('Post not found', 'danger')
    return redirect(ref)


@app.route('/posts/<id>/flag')
@login_required
def flag(id):
    ref = request.args.get("ref")
    post = Post.query.filter_by(id=id).first()
    if post and not current_user.has_flag(post):
        new_flag = Flags(post_id=id)
        current_user.flags.append(new_flag)
        db.session.add(new_flag)
        flash('Thank you! Your report has been recorded', 'info')
    elif current_user.has_flag(post):
        db.session.delete(flag)
        flash('You have removed a flag')
    db.session.commit()
    return redirect(ref)


@app.route('/user/<id>/follow', methods=['POST', 'GET'])
@login_required
def follow(id):
    if current_user.id == int(id):
        flash("You can't follow yourself", 'warning')
    else:
        existing = Follow.query.filter_by(
            followed_id=id, follower_id=current_user.id).first()
        if existing:
            db.session.delete(existing)
        else:
            new_follow = Follow(followed_id=id, follower_id=current_user.id)
            db.session.add(new_follow)
        db.session.commit()
    return redirect(url_for("profile", id=id))


@app.route("/edit/<id>", methods=["POST", "GET"])
@login_required
def edit(id):
    form = NewPost()
    post = Post.query.filter_by(id=id, author_id=current_user.id).first()
    if post:
        if request.method == "POST" and form.validate_on_submit():
            post.title = form.title.data
            post.body = form.body.data
            post.updated_on = datetime.now().now()
            db.session.commit()
            flash("Post successfully edited!", 'success')
        for field_name, errors in form.errors.items():
            flash(errors[0])
        return render_template("edit_form.html", form=form, post=post)
    else:
        flash("You are not authorized to edit this post", "danger")
    return redirect(url_for("posts"))


@app.route("/edit-comment/<id>", methods=['POST', "GET"])
@login_required
def edit_comment(id):
    form = NewComment()
    comment = Comment.query.filter_by(id=id).first()
    if current_user.id == comment.author_id:
        if request.method == "POST" and form.validate_on_submit():
            comment.body = form.body.data
            db.session.commit()
            return redirect(url_for("post", id=comment.post_id))
        for field_name, errors in form.errors.items():
            flash(errors[0], 'warning')
        return render_template("edit_comment.html", comment=comment, form=form)
    else:
        flash("You are not authorized to edit this comment", "danger")
    return redirect(url_for("post", id=comment.post_id))


@app.route("/delete/<id>", methods=["GET"])
@login_required
def delete(id):
    post = Post.query.filter_by(id=id, author_id=current_user.id).first()
    if post or current_user.is_admin:
        db.session.delete(post)
        db.session.commit()
        flash("Post successfully deleted!", 'success')
    else:
        flash("You are not authorized to delete this post", "danger")
    return redirect(url_for("posts"))


@app.route("/delete-comment/<id>", methods=['POST', 'GET'])
@login_required
def delete_comment(id):
    comment = Comment.query.filter_by(id=id).first()
    if current_user.id == comment.author_id or current_user.is_admin:
        db.session.delete(comment)
        db.session.commit()
        flash("Comment deleted!", 'warning')
    else:
        flash("You are not authorized to delete this comment", "danger")
    return redirect(url_for("post", id=comment.post_id))


if __name__ == '__main__':
    app.run(debug=True)
