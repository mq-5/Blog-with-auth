from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['SECRET_KEY'] = "secret"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
login = LoginManager(app)
db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128), index=True, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


db.create_all()


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
    return render_template("profile.html", user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
