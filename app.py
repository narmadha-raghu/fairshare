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
    password = db.Column(db.String(200), nullable=False)


# Group Models
class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    creator = db.relationship('User', backref='created_groups', foreign_keys=[created_by])

    def __repr__(self):
        return f"Group('{self.name}')"


class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    user = db.relationship('User', backref='group_memberships')
    group = db.relationship('Group', backref='members')

    def __repr__(self):
        return f"GroupMember(user_id={self.user_id}, group_id={self.group_id})"


# Expense Models
class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(255), nullable=False)
    payer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    payer = db.relationship('User', backref='expenses')
    group = db.relationship('Group', backref='expenses')


class ExpenseSplit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    expense_id = db.Column(db.Integer, db.ForeignKey('expense.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)

    expense = db.relationship('Expense', backref=db.backref('expense_splits', lazy=True))
    user = db.relationship('User', backref=db.backref('user_splits', lazy=True))

    def __init__(self, expense_id, user_id, amount):
        self.expense_id = expense_id
        self.user_id = user_id
        self.amount = amount


class Settlement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    payer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Who is paying
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Who receives money
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    payer = db.relationship('User', foreign_keys=[payer_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Helper Functions
def calculate_group_balances(group_id):
    """Calculate all balances within a group."""
    balances = {}

    # Get all expenses in this group
    expenses = Expense.query.filter_by(group_id=group_id).all()

    for expense in expenses:
        payer = expense.payer

        # Get splits for this expense
        splits = ExpenseSplit.query.filter_by(expense_id=expense.id).all()

        for split in splits:
            if split.user_id != payer.id:  # Skip if the user paid their own share
                # Create a key tuple (debtor, creditor)
                key = (split.user.username, payer.username)
                balances[key] = balances.get(key, 0) + split.amount

    return balances


# Authentication Routes
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password'])
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()

        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form["username"]
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('groups'))
        else:
            flash('Invalid credentials. Try again.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))


# Group Management Routes
@app.route('/groups')
@login_required
def groups():
    # Get all groups the user is a member of
    user_groups = Group.query.join(GroupMember).filter(GroupMember.user_id == current_user.id).all()
    # Get all groups created by the user
    created_groups = Group.query.filter_by(created_by=current_user.id).all()

    # Combine the lists, removing duplicates
    all_groups = list(set(user_groups + created_groups))

    return render_template('groups.html', groups=all_groups)


@app.route('/group/create', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']

        # Create new group
        new_group = Group(name=name, description=description, created_by=current_user.id)
        db.session.add(new_group)
        db.session.flush()  # This assigns the ID to new_group without committing

        # Add creator as a member
        membership = GroupMember(user_id=current_user.id, group_id=new_group.id)
        db.session.add(membership)

        db.session.commit()
        flash(f'Group "{name}" created successfully!', 'success')
        return redirect(url_for('group_details', group_id=new_group.id))

    return render_template('create_group.html')


@app.route('/group/<int:group_id>')
@login_required
def group_details(group_id):
    group = Group.query.get_or_404(group_id)

    # Check if user is a member of this group
    is_member = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first() is not None

    if not is_member and group.created_by != current_user.id:
        flash("You don't have access to this group.", 'danger')
        return redirect(url_for('groups'))

    # Get all members of the group
    members = User.query.join(GroupMember).filter(GroupMember.group_id == group_id).all()

    # Get all expenses in this group
    expenses = Expense.query.filter_by(group_id=group_id).order_by(Expense.timestamp.desc()).all()

    # Calculate balances within the group
    balances = calculate_group_balances(group_id)

    return render_template('group_details.html', group=group, members=members,
                           expenses=expenses, balances=balances)


@app.route('/group/<int:group_id>/add_member', methods=['GET', 'POST'])
@login_required
def add_group_member(group_id):
    group = Group.query.get_or_404(group_id)

    # Verify current user is the creator
    if group.created_by != current_user.id:
        flash("Only the group creator can add members.", 'danger')
        return redirect(url_for('group_details', group_id=group_id))

    if request.method == 'POST':
        username = request.form['username']

        # Check if user already exists
        user = User.query.filter_by(username=username).first()

        if not user:
            # Generate a temporary password
            import secrets
            import string
            temp_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))
            hashed_password = bcrypt.generate_password_hash(temp_password)

            # Create a new user
            user = User(username=username, password=hashed_password)
            db.session.add(user)
            db.session.flush()  # Get the user ID

            flash(f'New user "{username}" created. They will need to reset their password when they join.', 'info')

        # Check if already a member
        existing_member = GroupMember.query.filter_by(user_id=user.id, group_id=group_id).first()
        if existing_member:
            flash(f'{username} is already a member of this group.', 'warning')
            return redirect(url_for('group_details', group_id=group_id))

        # Add new member
        new_member = GroupMember(user_id=user.id, group_id=group_id)
        db.session.add(new_member)
        db.session.commit()

        flash(f'{username} added to the group!', 'success')
        return redirect(url_for('group_details', group_id=group_id))

    return render_template('add_group_member.html', group=group)


# Group Expense Routes
@app.route('/group/<int:group_id>/add_expense', methods=['GET', 'POST'])
@login_required
def add_group_expense(group_id):
    group = Group.query.get_or_404(group_id)

    # Check if user is a member of this group
    is_member = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first() is not None

    if not is_member and group.created_by != current_user.id:
        flash("You don't have access to this group.", 'danger')
        return redirect(url_for('groups'))

    # Get all members of the group
    group_members = User.query.join(GroupMember).filter(GroupMember.group_id == group_id).all()

    if request.method == 'POST':
        amount = float(request.form['amount'])
        description = request.form['description']
        payer_id = int(request.form['payer_id'])
        split_type = request.form['split_type']

        # Create new expense
        new_expense = Expense(
            amount=amount,
            description=description,
            payer_id=payer_id,
            group_id=group_id
        )

        db.session.add(new_expense)
        db.session.flush()  # Get the expense ID without committing

        # Handle expense splits
        if split_type == 'equal':
            # Equal split among all group members
            per_person = amount / len(group_members)

            for member in group_members:
                # The payer doesn't owe themselves money
                if member.id != payer_id:
                    new_split = ExpenseSplit(
                        expense_id=new_expense.id,
                        user_id=member.id,
                        amount=per_person
                    )
                    db.session.add(new_split)

        elif split_type == 'custom':
            # Handle custom splits
            for member in group_members:
                # Skip the payer in custom splits
                if member.id != payer_id:
                    split_amount = request.form.get(f'custom_split_{member.id}', 0)

                    if split_amount and float(split_amount) > 0:
                        new_split = ExpenseSplit(
                            expense_id=new_expense.id,
                            user_id=member.id,
                            amount=float(split_amount)
                        )
                        db.session.add(new_split)

        db.session.commit()
        flash('Expense added successfully!', 'success')
        return redirect(url_for('group_details', group_id=group_id))

    return render_template('add_group_expense.html', group=group, members=group_members)


# Group Settlement Routes
@app.route('/group/<int:group_id>/settle', methods=['GET', 'POST'])
@login_required
def group_settle(group_id):
    group = Group.query.get_or_404(group_id)

    # Check if user is a member of this group
    is_member = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first() is not None

    if not is_member and group.created_by != current_user.id:
        flash("You don't have access to this group.", 'danger')
        return redirect(url_for('groups'))

    # Get all members of the group
    members = User.query.join(GroupMember).filter(GroupMember.group_id == group_id).all()

    if request.method == 'POST':
        payer_id = int(request.form['payer_id'])
        receiver_id = int(request.form['receiver_id'])
        amount = float(request.form['amount'])

        if payer_id == receiver_id:
            flash("Payer and receiver cannot be the same person.", 'danger')
            return redirect(url_for('group_settle', group_id=group_id))

        # Verify both users are in the group
        payer_in_group = GroupMember.query.filter_by(user_id=payer_id, group_id=group_id).first() is not None
        receiver_in_group = GroupMember.query.filter_by(user_id=receiver_id, group_id=group_id).first() is not None

        if not payer_in_group or not receiver_in_group:
            flash("Both users must be members of this group.", 'danger')
            return redirect(url_for('group_settle', group_id=group_id))

        # Find expense splits where payer owes money to receiver
        # This means finding expenses where:
        # 1. Receiver paid for the expense
        # 2. Payer has a split (owes money) for that expense
        splits = ExpenseSplit.query.join(Expense).filter(
            ExpenseSplit.user_id == payer_id,
            Expense.payer_id == receiver_id,
            Expense.group_id == group_id,
            ExpenseSplit.amount > 0
        ).order_by(ExpenseSplit.amount.asc()).all()

        if not splits:
            flash(f"No outstanding balance found from selected payer to receiver in this group.", 'danger')
            return redirect(url_for('group_settle', group_id=group_id))

        # Process settlement
        remaining_amount = amount

        for split in splits:
            if remaining_amount >= split.amount:
                # This split can be fully settled
                remaining_amount -= split.amount
                split.amount = 0
            else:
                # This split can only be partially settled
                split.amount -= remaining_amount
                remaining_amount = 0

            db.session.add(split)

            if remaining_amount <= 0:
                break

        # Clean up any fully settled splits
        db.session.commit()
        ExpenseSplit.query.filter_by(amount=0).delete()

        # Create settlement record
        new_settlement = Settlement(
            payer_id=payer_id,
            receiver_id=receiver_id,
            amount=amount
        )
        db.session.add(new_settlement)
        db.session.commit()

        # Get user names for the flash message
        payer = User.query.get(payer_id)
        receiver = User.query.get(receiver_id)

        flash(f"{payer.username} successfully settled ₹{amount} with {receiver.username}!", 'success')
        return redirect(url_for('group_details', group_id=group_id))

    # Calculate balances for this group
    balances = calculate_group_balances(group_id)

    return render_template('group_settle.html', group=group, members=members, balances=balances)


@app.route('/group/<int:group_id>/settle_all', methods=['POST'])
@login_required
def group_settle_all(group_id):
    group = Group.query.get_or_404(group_id)

    # Check if user is a member of this group
    is_member = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first() is not None

    if not is_member and group.created_by != current_user.id:
        flash("You don't have access to this group.", 'danger')
        return redirect(url_for('groups'))

    # Find all expense splits where the current user owes money in this group
    user_splits = ExpenseSplit.query.join(Expense).filter(
        ExpenseSplit.user_id == current_user.id,
        Expense.group_id == group_id,
        ExpenseSplit.amount > 0
    ).all()

    if not user_splits:
        flash("You have no outstanding balances in this group.", 'info')
        return redirect(url_for('group_details', group_id=group_id))

    # Calculate total amount owed
    total_owed = sum(split.amount for split in user_splits)

    # Create settlement records for each expense owner
    settlements_by_receiver = {}

    for split in user_splits:
        receiver_id = split.expense.payer_id
        if receiver_id in settlements_by_receiver:
            settlements_by_receiver[receiver_id] += split.amount
        else:
            settlements_by_receiver[receiver_id] = split.amount

    # Create settlement records
    for receiver_id, amount in settlements_by_receiver.items():
        new_settlement = Settlement(
            payer_id=current_user.id,
            receiver_id=receiver_id,
            amount=amount
        )
        db.session.add(new_settlement)

    # Delete all the splits
    for split in user_splits:
        db.session.delete(split)

    db.session.commit()

    flash(f"You have settled all your debts in this group (₹{total_owed:.2f}).", 'success')
    return redirect(url_for('group_details', group_id=group_id))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)