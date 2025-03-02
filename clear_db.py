from app import app, db
from sqlalchemy import inspect


def reset_database():
    """
    Drops all tables EXCEPT User and recreates them with the current model definitions.
    This preserves existing user accounts.
    """
    with app.app_context():
        inspector = inspect(db.engine)
        table_names = inspector.get_table_names()

        # Tables to preserve (lowercase for case-insensitive comparison)
        preserve_tables = ['user']

        # Get tables to drop (all except those in preserve_tables)
        tables_to_drop = [table for table in table_names if table.lower() not in preserve_tables]

        if tables_to_drop:
            print(f"Dropping tables: {', '.join(tables_to_drop)}")

            # Generate drop statements
            for table in tables_to_drop:
                db.engine.execute(f'DROP TABLE IF EXISTS {table}')

            print("Tables dropped successfully")
        else:
            print("No tables to drop")

        print("Creating all tables with updated schema...")
        db.create_all()

        print("Database reset completed successfully!")
        print("User accounts have been preserved.")


if __name__ == "__main__":
    reset_database()