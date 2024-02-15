import os
import re  #

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd
from datetime import datetime


# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    user_info = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    cash_balance = user_info[0]["cash"]

    stocks = db.execute(
        """
        SELECT symbol, SUM(shares) AS shares , price, SUM(shares * price) AS total, time FROM purchases
        WHERE user_id = ?
        GROUP BY symbol
        HAVING shares > 0

    """,
        user_id,
    )
    return render_template("index.html", database=stocks, cash=usd(cash_balance))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")

    else:
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol:  # check if he enter a symbol
            return apology("please enter a Symbol")
        if (
            not shares or not shares.isdigit() or int(shares) <= 0
        ):  # check if he enter a share and if this share isdigit and if fractional
            return apology("please enter a positive number of shares")

        stock = lookup(symbol)
        # check if symbol exist
        if stock == None:
            return apology("Symbol don't exist")

        price = stock["price"]
        total_cost = int(shares) * price

        # Get the user's cash balance from the database
        user_id = session["user_id"]
        user_info = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        cash_balance = user_info[0]["cash"]

        # Check if the user can afford the purchase
        if total_cost > cash_balance:
            return apology("Insufficient funds to complete the purchase")

        # Update the user's cash balance after the purchase
        new_cash_balance = cash_balance - total_cost
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash_balance, user_id)

        # Add into the table the purchases
        db.execute(
            "INSERT INTO purchases (user_id, symbol, shares, price, time) VALUES (?, ?, ?, ?, ?)",
            user_id,
            stock["symbol"],
            shares,
            price,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        flash("Buy Succefully")  # for a flash message

        # Redirect the user to the home page
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    purchases_db = db.execute("SELECT * FROM purchases WHERE user_id = ?", user_id)
    return render_template("history.html", purchases=purchases_db)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")

    else:
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("please enter a Symbol")

        stock = lookup(symbol)  # use helpers.py

        if stock == None:
            return apology("Symbol don't exist")

        return render_template(
            "quoted.html",
            name=stock["name"],
            symbol=stock["symbol"],
            price=usd(stock["price"]),
        )  # that's the final output for the price of the symbols


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    else:
        username = request.form.get("username")
        password = request.form.get("password")
        confirmpassword = request.form.get("confirmation")

        if not username:
            return apology("Please Enter a Username")

        if not password:
            return apology("Please Enter a password")

        if not confirmpassword:
            return apology("Please Enter a confirmation")

        if password != confirmpassword:
            return apology("Please Enter a correct Confirmation")
        # Define the password strength pattern
        # The pattern below requires at least one letter, one number, and one symbol
        password_pattern = (
            r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$"
        )

        # Check if the password matches the required format
        if not re.search(password_pattern, password):
            return apology(
                "Password must contain at least 8 characters with at least one letter, one number, and one symbol."
            )
        # till here for password strength

        hash = generate_password_hash(password)  # generate hash pass for security

        try:
            users = db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?)", username, hash
            )  # insert into db

        except:  # if username exist return apology
            return apology("Username Allready Exist Try another One")

        session["user_id"] = users  # redirect to the home page part
        return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        user_id = session["user_id"]
        stocks = db.execute(
            "SELECT symbol FROM purchases WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0 ORDER BY symbol ASC",
            user_id,
        )

        return render_template("sell.html", stocks=stocks)

    else:
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        if not symbol:  # check if he enter a symbol
            return apology("please enter a Symbol")
        if not shares:  # check if he enter a share
            return apology("please enter a valid number of shares")

        stock = lookup(symbol)
        # check if symbol exist
        if stock == None:
            return apology("Symbol don't exist")

        price = stock["price"]
        total_cost = int(shares) * price

        # Get the user's cash balance from the database
        user_id = session["user_id"]
        user_info = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        cash_balance = user_info[0]["cash"]

        user_shares = db.execute(
            "SELECT shares FROM purchases WHERE user_id = ? AND symbol = ? GROUP BY symbol",
            user_id,
            symbol,
        )
        shares_in_the_moment = int(user_shares[0]["shares"])

        if shares_in_the_moment < shares:
            return apology("you don't have that much stocks right now")

        # Add into the table the purchases
        db.execute(
            "INSERT INTO purchases (user_id, symbol, shares, price, time) VALUES (?, ?, ?, ?, ?)",
            user_id,
            stock["symbol"],
            -int(shares),
            price,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        # Update the user's cash balance after the sell
        new_cash_balance = cash_balance + total_cost
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash_balance, user_id)

        flash("Sold Succefully")  # for a flash message

        # Redirect the user to the home page
        return redirect("/")
