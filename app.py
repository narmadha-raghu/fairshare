from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fairshare.db'
app.config['SECRET_KEY'] = 'your_secret_key'

# Initialize database and authentication
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(255), nullable=False)
    payer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    payer = db.relationship('User', backref='expenses')


class Split(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    expense_id = db.Column(db.Integer, db.ForeignKey('expense.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Who owes money
    amount = db.Column(db.Float, nullable=False)

    expense = db.relationship('Expense', backref='splits')
    user = db.relationship('User', backref='splits')


class Settlement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    payer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Who is paying
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Who receives money
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    payer = db.relationship('User', foreign_keys=[payer_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])


class ExpenseSplit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    expense_id = db.Column(db.Integer, db.ForeignKey('expense.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)

    expense = db.relationship('Expense', backref=db.backref('expense_splits', lazy=True))  # Renamed from 'splits'
    user = db.relationship('User', backref=db.backref('user_splits', lazy=True))  # Renamed from 'splits'

    def __init__(self, expense_id, user_id, amount):
        self.expense_id = expense_id
        self.user_id = user_id
        self.amount = amount


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password'])

        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()

        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):  # ✅ Use Flask-Bcrypt
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Try again.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))


@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    users = User.query.all()
    if request.method == 'POST':
        amount = float(request.form['amount'])
        description = request.form['description']
        payer_id = int(request.form['payer_id'])
        split_type = request.form['split_type']

        new_expense = Expense(amount=amount, description=description, payer_id=payer_id)
        db.session.add(new_expense)
        db.session.commit()

        if split_type == 'equal':
            per_person = amount / len(users)
            for user in users:
                if user.id != payer_id:
                    new_split = ExpenseSplit(expense_id=new_expense.id, user_id=user.id, amount=per_person)
                    db.session.add(new_split)

        elif split_type == 'custom':
            custom_splits = request.form.getlist('custom_split')
            for user_id, split_amount in custom_splits.items():
                if float(split_amount) > 0:
                    new_split = ExpenseSplit(expense_id=new_expense.id, user_id=int(user_id),
                                             amount=float(split_amount))
                    db.session.add(new_split)

        db.session.commit()
        flash('Expense added successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_expense.html', users=users)


@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_authenticated:
        flash("You need to log in first.", "danger")
        return redirect(url_for('login'))  # Redirect to login if not authenticated

    expenses = Expense.query.all()
    users = User.query.all()
    balances = {}

    for expense in expenses:
        payer = expense.payer

        # ✅ Fetch only unsettled splits
        splits = ExpenseSplit.query.filter(
            ExpenseSplit.expense_id == expense.id,
            ExpenseSplit.amount > 0  # Ignore fully settled splits
        ).all()

        if not splits:
            continue  # Skip this expense

        for split in splits:
            if split.user != payer:
                key = (split.user.username, payer.username)
                balances[key] = balances.get(key, 0) + split.amount  # ✅ Use actual remaining amount

    return render_template('dashboard.html', expenses=expenses, users=users, balances=balances,
                           payer_id=current_user.id)


@app.route('/settle', methods=['POST'])
@login_required
def settle():
    payer_id = int(request.form.get('payer_id'))
    receiver_id = int(request.form.get('receiver_id'))
    amount = float(request.form.get('amount'))

    if not payer_id or not receiver_id or not amount:
        flash("Invalid settlement request.", "danger")
        return redirect(url_for('dashboard'))

    if payer_id == receiver_id:
        flash("Payer and Receiver cannot be the same.", "danger")
        return redirect(url_for('dashboard'))

    payer = User.query.get(payer_id)
    receiver = User.query.get(receiver_id)

    if not payer or not receiver:
        flash("Invalid users selected.", "danger")
        return redirect(url_for('dashboard'))

    # ✅ Fetch unsettled splits where receiver owes payer
    splits = ExpenseSplit.query.filter(
        ExpenseSplit.user_id == receiver_id,
        ExpenseSplit.expense.has(payer_id=payer_id),
        ExpenseSplit.amount > 0  # Only consider non-zero amounts
    ).order_by(ExpenseSplit.amount.asc()).all()

    if not splits:
        flash("No outstanding balance found between selected users.", "danger")
        return redirect(url_for('dashboard'))

    remaining_amount = amount  # Amount being settled

    for split in splits:
        if remaining_amount >= split.amount:
            remaining_amount -= split.amount
            split.amount = 0  # Fully settle this split
        else:
            split.amount -= remaining_amount  # Reduce the split amount
            db.session.add(split)  # ✅ Ensure the updated split is tracked
            break

        db.session.add(split)  # ✅ Track all updates

    # ✅ Delete fully settled splits after updates
    db.session.commit()
    ExpenseSplit.query.filter(ExpenseSplit.amount == 0).delete()
    db.session.commit()

    flash(f"{payer.username} successfully settled ₹{amount} with {receiver.username}!", "success")
    return redirect(url_for('dashboard'))


@app.route('/settle_all', methods=['POST'])
@login_required
def settle_all():
    # Get all expense splits for the current user
    user_splits = ExpenseSplit.query.filter_by(user_id=current_user.id).all()

    # Check if user owes any money
    total_owed = 0
    for split in user_splits:
        # If current user is not the payer of this expense, add to total owed
        if split.expense.payer_id != current_user.id:
            total_owed += split.amount

    if total_owed == 0:
        flash('You have no outstanding balances to settle!', 'warning')
        return redirect(url_for('dashboard'))

    # Remove only the current user's splits
    for split in user_splits:
        db.session.delete(split)

    db.session.commit()
    flash(f'Your share of expenses (₹{total_owed}) has been settled!', 'success')
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
