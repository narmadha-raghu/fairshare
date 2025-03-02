from app import app, db


def reset_database():
    """
    Drops all tables and recreates them with the current model definitions.
    WARNING: This will delete all existing data!
    """
    with app.app_context():
        print("Dropping all tables...")
        db.drop_all()

        print("Creating all tables with updated schema...")
        db.create_all()

        print("Database reset completed successfully!")


if __name__ == "__main__":
    reset_database()