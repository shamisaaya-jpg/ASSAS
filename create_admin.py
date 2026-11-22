"""Create (or reset) an ASSAS admin account.

Usage:  python create_admin.py
"""
from getpass import getpass

from werkzeug.security import generate_password_hash

import db


def main():
    db.init_db()
    username = input("Admin username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return

    password = getpass("Password (min 8 characters): ")
    if len(password) < 8:
        print("Password too short.")
        return
    if password != getpass("Confirm password: "):
        print("Passwords do not match.")
        return

    db.create_user(username, generate_password_hash(password))
    print(f"Admin '{username}' is ready. You can log in to ASSAS now.")


if __name__ == "__main__":
    main()
