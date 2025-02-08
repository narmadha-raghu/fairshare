from app import app, db
from app import User, Expense, ExpenseSplit
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)

def create_test_data():
    with app.app_context():
        # Ensure database exists
        db.create_all()

        # Check if users already exist
        if User.query.count() > 0:
            print("Test data already exists!")
            return

        # Step 1: Create Users
        alice = User(
            username="Alice",
            email="alice@example.com",
            password=bcrypt.generate_password_hash("test123").decode('utf-8')
        )
        bob = User(
            username="Bob",
            email="bob@example.com",
            password=bcrypt.generate_password_hash("test123").decode('utf-8')
        )
        cath = User(
            username="Cath",
            email="cath@example.com",
            password=bcrypt.generate_password_hash("test123").decode('utf-8')
        )

        db.session.add_all([alice, bob, cath])
        db.session.commit()

        print("✅ Users created: Alice, Bob, Cath")

        # Step 2: Add Lunch Expense (₹3000) - Paid by Alice, Split Equally
        lunch = Expense(description="Lunch", amount=3000, payer_id=alice.id)
        db.session.add(lunch)
        db.session.commit()

        # Create equal splits (₹1000 each)
        for user in [alice, bob, cath]:
            split = ExpenseSplit(expense_id=lunch.id, user_id=user.id, amount=1000)
            db.session.add(split)

        print("✅ Lunch expense added (₹3000, split equally)")

        # Final Commit
        db.session.commit()
        print("🎉 Test data successfully added!")

if __name__ == "__main__":
    create_test_data()