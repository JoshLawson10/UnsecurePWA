import sqlite3 as sql


def insertUser(username, password, DoB):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (username,password,dateOfBirth) VALUES (?,?,?)",
        (username, password, DoB),
    )
    con.commit()
    con.close()


def retrieveUsers(username, password):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    query = f"""
    SELECT * FROM users
    WHERE username = '{username}'
    AND password = '{password}'
    """
    cur.execute(query)

    result = cur.fetchone()
    con.close()

    if result:
        return True
    else:
        return False


def insertFeedback(feedback):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(f"INSERT INTO feedback (feedback) VALUES ('{feedback}')")
    con.commit()
    con.close()


def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()
    f = open("templates/partials/success_feedback.html", "w")
    for row in data:
        f.write("<p>\n")
        f.write(f"{row[1]}\n")
        f.write("</p>\n")
    f.close()
