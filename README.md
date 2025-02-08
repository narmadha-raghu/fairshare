# FairShare: A Web-Based Expense Splitting and Settlement Platform

## Overview
FairShare is a web-based application designed to simplify group expense management by providing an easy-to-use platform for tracking, splitting, and settling shared costs. The application supports equal and custom splitting, ensuring transparency and accuracy in transactions.

## Features
- User authentication (Signup, Login, Logout)
- Create and manage groups
- Add and split expenses equally or custom
- Track outstanding balances
- Settle payments between users
- Dashboard with expense and balance summary

## Installation Guide (Windows)

### Prerequisites
- Install **Python 3.8+** from [Python's official website](https://www.python.org/)
- Install **pip** (comes with Python by default)
- Install **virtualenv** (optional but recommended for isolated environments)

### Steps to Install & Run

1. **Clone the Repository**
   ```sh
   git clone https://github.com/narmadha-raghu/fairshare.git
   cd fairshare
   ```

2. **Create and Activate Virtual Environment**
   ```sh
   python -m venv venv
   venv\Scripts\activate  # For Windows
   ```

3. **Install Required Dependencies**
   ```sh
   pip install -r requirements.txt
   ```

4. **Set Environment Variables**
   ```sh
   set FLASK_APP=app.py
   set FLASK_ENV=development
   ```

5. **Run the Application**
   ```sh
   flask run
   ```

6. Open your browser and go to: **`http://127.0.0.1:5000`**

## API Routes & Endpoints

### Authentication
- `GET http://127.0.0.1:5000/signup` → Display signup form
- `POST http://127.0.0.1:5000/signup` → Register a new user
- `GET http://127.0.0.1:5000/login` → Display login form
- `POST http://127.0.0.1:5000/login` → Authenticate and log in user
- `GET http://127.0.0.1:5000/logout` → Logout the current user

### Dashboard & Expenses
- `GET http://127.0.0.1:5000/dashboard` → View all expenses, balances, and settlement options
- `GET http://127.0.0.1:5000/add_expense` → Display form to add a new expense
- `POST http://127.0.0.1:5000/add_expense` → Create a new expense and split among users

### Settlements
- `POST http://127.0.0.1:5000/settle` → Settle a partial or full amount between two users
- `POST http://127.0.0.1:5000/settle_all` → Clear all balances and settle everything

