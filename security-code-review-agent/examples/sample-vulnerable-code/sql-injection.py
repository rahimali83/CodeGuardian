# Example of SQL Injection Vulnerability
# This file demonstrates common SQL injection patterns for testing security reviews

import sqlite3

def get_user_by_username_insecure(username):
    """
    INSECURE - SQL Injection vulnerability using string concatenation
    An attacker could input: admin' OR '1'='1
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # VULNERABILITY: String concatenation in SQL query
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)

    return cursor.fetchone()


def get_user_by_id_insecure(user_id):
    """
    INSECURE - SQL Injection using % formatting
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # VULNERABILITY: String formatting in SQL query
    query = "SELECT * FROM users WHERE id = %s" % user_id
    cursor.execute(query)

    return cursor.fetchone()


def search_products_insecure(search_term):
    """
    INSECURE - SQL Injection in search functionality
    """
    conn = sqlite3.connect('products.db')
    cursor = conn.cursor()

    # VULNERABILITY: User input directly in query
    query = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
    cursor.execute(query)

    return cursor.fetchall()


# SECURE EXAMPLES (for comparison)

def get_user_by_username_secure(username):
    """
    SECURE - Uses parameterized query to prevent SQL injection
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # SECURE: Parameterized query
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))

    return cursor.fetchone()


def search_products_secure(search_term):
    """
    SECURE - Parameterized query with LIKE
    """
    conn = sqlite3.connect('products.db')
    cursor = conn.cursor()

    # SECURE: Parameterized query
    query = "SELECT * FROM products WHERE name LIKE ?"
    cursor.execute(query, (f'%{search_term}%',))

    return cursor.fetchall()
