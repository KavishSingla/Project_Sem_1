from flask import Flask, render_template, redirect, request, url_for, flash , jsonify
from flask_sqlalchemy import SQLAlchemy
import os
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from functools import wraps
import re
from flask_jwt_extended import JWTManager, create_access_token






basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)


app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + \
    os.path.join(basedir, "app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["SECRET_KEY"] = "Your secret key"
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'

jwt = JWTManager(app)
db = SQLAlchemy(app)

bcrypt = Bcrypt(app)
login_manager = LoginManager()

login_manager.init_app(app)

login_manager.login_view = "login"


class User(db.Model, UserMixin):

    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)
    mobile = db.Column(db.String(15), nullable=False)
    gender = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="user")


    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    


class Contact(db.Model):
    __tablename__ = "contact"

    contactid = db.Column(db.Integer, primary_key=True)
    name_contact = db.Column(db.String(100), nullable=False)
    email_contact = db.Column(db.String(100), nullable=False, unique=True)
    msg = db.Column(db.String(100), nullable=False)


    def __repr__(self):
        return f"ContactId: {self.contactid} Msg: {self.msg}"
    
    

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))    
    



with app.app_context():
    db.create_all()



    if not User.query.filter_by(role="admin").first():
            admin_user = User(name="Admin", email="admin@gmail.com",mobile="1234567890",gender='Male', role="admin")
            admin_user.set_password("admin123")  # Set a default password
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created with email: admin@gmail.com and password: admin123")




@app.route("/")
def home():
    return render_template("index.html")


@app.route("/check")
def check_it_out():
    return render_template("investing.html")


# @app.route("/contact")
# def contact():
#     return render_template("contact.html")


# @app.route("/aboutus")
# def aboutus():
#     return render_template("about.html")

@app.route("/calculator")
@login_required
def calculator():
    return render_template("cal_page.html")


@app.route("/credit")
@login_required
def credit():
    return render_template("credit_cards.html")


@app.route("/emi")
@login_required
def emi():
    return render_template("emiCalculator.html")



@app.route("/fd")
@login_required
def fd():
    return render_template("fdCalculator.html")



@app.route("/rd")
@login_required
def rd():
    return render_template("rdCalculator.html")


@app.route("/savings")
@login_required
def savings():
    return render_template("savingscalculator.html")



@app.route("/sip")
@login_required
def sip():
    return render_template("sipCalculator.html")


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html",user = current_user)



@app.route("/networth")
def networth():
    return render_template("networth.html")


@app.route("/contactinfo" , methods=["POST"])
def contact_info():
    flash("Thanks for your feedback", "success")
    return redirect(url_for("home"))


@app.route("/apply")
@login_required
def apply():
    flash("Thanks for applying the card , details will be shared on your email ", "info")
    return redirect(url_for("home"))



@app.errorhandler(404)
def page_not_found(e):
  print(e) 
  return render_template("404.html"), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template("500.html"), 500


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        mobile = request.form.get("mobile")
        gender = request.form.get("gender")
        

      
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("register"))

       
        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for("register"))
        
        if not re.match(r"^(?=.*[!@#$%^&*(),.?\":{}|<>])(?=.*\d)[A-Za-z\d!@#$%^&*(),.?\":{}|<>]{8,}$", password):
            flash("Password must be at least 8 characters long, include one number and one special character.", "danger")
            return redirect(url_for("register"))
        
        new_user = User(name=name, email=email, mobile=mobile, gender = gender)
        new_user.set_password(password) 
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")




@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        
        
        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role")
        

        user = User.query.filter_by(email=email , role = role).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid credentials!", "danger")

    return render_template("login.html")
           

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.role != 'admin':
            flash("Access denied!", "danger")
            return redirect(url_for('dashboard'))
        return func(*args, **kwargs)
    return wrapper


@app.route("/update/<int:id>", methods=["GET", "POST"])
@login_required
def update(id):
    user = db.session.get(User, id)
    if request.method == "POST":
        name = request.form.get("name")
        gender = request.form.get("gender")
        mobile = request.form.get("mobile")
        

        user.name = name
        user.gender = gender
        user.mobile = mobile
        

        db.session.add(user)
        db.session.commit()
        flash("Profile Updated", "info")
        return redirect(url_for("profile"))

    return render_template("update_user.html", user = user)
    


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for("home"))


@app.route("/delete/<int:id>")
@login_required

def delete(id):
    user = db.session.get(User, id)
    db.session.delete(user)
    db.session.commit()
    flash("Profile deleted successfully!", "success")
    return redirect(url_for("home"))




# @app.route("/contact" , methods=["GET" , "POST"])
# def contact():
#     if request.method == "POST":
#         name_contact = request.form.get("name")
#         email_contact = request.form.get("email")
#         msg = request.form.get("msg")
#         new_msg = Contact(msg = msg , name = name_contact , email = email_contact )
#         db.session.add(new_msg)
#         db.session.commit()
#         flash("Message sent successfully!", "success")
#         return redirect(url_for("home"))
#     return render_template("contact.html")






@app.route("/aboutus" , methods=['GET'])
def aboutus():
    about_info = {
        "application_name": "BudgetBee",
        "description": "Making progress is hard work. That’s why we believe in a world where technology and data can help make finances easier for everyone. It’s our mission to empower each and every one of our members with the knowledge, tips and tools they need to turn their financial dreams into a reality ",
        "mission": "we believe that managing personal finances should be effortless and empowering. Our smart finance tracker is designed to help you take control of your money, track your expenses, set budgets, and achieve your financial goals all in one place.",
        "vision": " We know that financial planning can be overwhelming, but with BudgetBee’s intuitive tools, you can visualize your spending, monitor savings, and make informed financial decisions with ease. Whether you’re a student, a working professional, or managing a household, our platform adapts to your needs.",
        "goals": [
            "Security and simplicity are at the heart of BudgetBee. Your data is protected with bank-level encryption, and our user-friendly interface ensures that budgeting becomes a habit—not a hassle. With insightful analytics, reminders, and custom financial goals, BudgetBee helps you spend wisely and save smarter.",
            "Take the first step toward financial freedom today! Join thousands of users who trust BudgetBee to track their expenses, cut unnecessary costs, and build a stable financial future. Because when it comes to money every small step counts.",
            
        ],
        "contact": {
            "email": "BudgetBee@gmail.com",
            "phone": "1234567890"
        }
    }
    return jsonify(about_info)


@app.route("/contactapi" , methods=[ "POST"])
def contact_api():
    data = request.get_json(force=True, silent=True) or {}
    name_contact = data.get("name_contact")
    email_contact = data.get("email_contact")
    msg = data.get("msg")
    if not msg:
        return jsonify({"error": "message is required"}), 400

    if Contact.query.filter_by(email_contact=email_contact).first():
        return jsonify({"error": "Email already exists"}), 400
        
    new_msg = Contact( name_contact = name_contact , email_contact = email_contact , msg = msg )
    db.session.add(new_msg)
    db.session.commit()
    return jsonify({"message": "Message Sent successful!"}), 200


@app.route('/allcontactsapi', methods=['GET'])
def get_all_contacts():
    contacts = Contact.query.all()
    data = [
        {
            'id': contact.contactid,
            'name_contact': contact.name_contact,
            'email_contact': contact.email_contact,
            'msg': contact.msg
        }
        for contact in contacts
    ]
    return jsonify(data), 200




# @app.route("/registerapi", methods=["POST"])
# def register_api():
#     data = request.get_json(force=True, silent=True) or {}

#     name = data.get("name")
#     email = data.get("email")
#     password = data.get("password")
#     mobile = data.get("mobile")
#     gender = data.get("gender")

#     if not all([name, email, password, mobile, gender]):
#         return jsonify({"error": "All fields are required"}), 400

#     if User.query.filter_by(email=email).first():
#         return jsonify({"error": "Email already exists"}), 400

#     new_user = User(name=name, email=email, mobile=mobile, gender=gender)
#     new_user.set_password(password)
#     db.session.add(new_user)
#     db.session.commit()

#     return jsonify({"message": "Registration successful!"}), 200



# @app.route("/loginapi", methods=["POST"])
# def login_api():
#     data = request.get_json()

#     email = data.get("email")
#     password = data.get("password")
#     role = data.get("role")

#     if not all([email, password, role]):
#         return jsonify({"error": "Email, password, and role are required"}), 400

#     user = User.query.filter_by(email=email, role=role).first()
#     if user and user.check_password(password):
#         access_token = create_access_token(identity={"id": user.id, "email": user.email, "role": user.role})
#         return jsonify({
#             "access_token": access_token,
#             "message": "Login successful"
#         }), 200
#     else:
#         return jsonify({"error": "Invalid credentials"}), 401





if __name__ == "__main__":
    app.run(debug=True)
