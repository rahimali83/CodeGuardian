#  Copyright (c) ${YEAR} Virtuous BPO Software Projects
# 
#   All rights reserved.
# 
#   This software and associated documentation files (the "Software") are proprietary to Virtuous BPO Software Projects and are protected by copyright law and international treaty provisions. Unauthorized reproduction or distribution of this Software, or any portion of it, may result in severe civil and criminal penalties, and will be prosecuted to the maximum extent possible under the law.
# 
#  RESTRICTED RIGHTS: Use, duplication, or disclosure by the government is subject to restrictions as set forth in subparagraph (c)(1)(ii) of the Rights in Technical Data and Computer Software clause at DFARS 252.227-7013 or subparagraphs (c)(1) and (2) of the Commercial Computer Software-Restricted Rights clause at FAR 52.227-19, as applicable.
# 
#   * Contact: info@virtuousbpo.com
#   * Website: www.virtuousbpo.com
# 
#   * Project: ${PROJECT_NAME}
#   * File: ${FILE_NAME}
#   * Created: ${DATE}
#   * Author: ${USER}

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
