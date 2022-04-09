import werkzeug.security
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory , session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)



app.config['SECRET_KEY'] = '5cx4456tg7x49xg7'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template("index.html" , logged_in=False)


@app.route('/register', methods=["POST", "GET"])
def register():
    if request.method == "POST":
        if User.query.filter_by(email=request.form.get('email')).first():
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        user_password = request.form.get('password')
        password = generate_password_hash(password=user_password, method='pbkdf2:sha256', salt_length=8 )
        new_user = User(
            email=request.form.get('email'),
            name=request.form.get('name'),
            password=password
        )
        db.session.add(new_user)
        db.session.commit()
        login.user(new_user)

        return redirect(url_for("secrets"))
    return render_template("register.html" , logged_in=False)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("username doesnt exist!")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash("passwordd incorrect")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('secrets'))
    return render_template("login.html", logged_in=False)


@app.route('/secrets')
def secrets():
    return render_template("secrets.html", name=current_user.name ,logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
def download():
    return send_from_directory('static', filename="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
