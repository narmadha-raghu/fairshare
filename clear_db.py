from app import app, db
from app import User, Expense, ExpenseSplit, Split, Settlement


def clear_database():
    with app.app_context():
        # Ensure database exists
        db.create_all()

        print("Starting database cleanup...")

        # Delete all ExpenseSplit entries
        try:
            expense_split_count = ExpenseSplit.query.count()
            ExpenseSplit.query.delete()
            print(f"✓ Deleted {expense_split_count} ExpenseSplit records")
        except Exception as e:
            print(f"Error deleting ExpenseSplit records: {e}")

        # Delete all Split entries
        try:
            split_count = Split.query.count()
            Split.query.delete()
            print(f"✓ Deleted {split_count} Split records")
        except Exception as e:
            print(f"Error deleting Split records: {e}")

        # Delete all Settlement entries
        try:
            settlement_count = Settlement.query.count()
            Settlement.query.delete()
            print(f"✓ Deleted {settlement_count} Settlement records")
        except Exception as e:
            print(f"Error deleting Settlement records: {e}")

        # Delete all Expense entries
        try:
            expense_count = Expense.query.count()
            Expense.query.delete()
            print(f"✓ Deleted {expense_count} Expense records")
        except Exception as e:
            print(f"Error deleting Expense records: {e}")

        # Commit all changes
        db.session.commit()

        # Confirm user data is intact
        user_count = User.query.count()
        print(f"✓ Preserved {user_count} User records")

        print("🎉 Database cleanup complete! All tables cleared except Users.")


if __name__ == "__main__":
    clear_database()