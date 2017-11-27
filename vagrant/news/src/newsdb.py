# Data acces layer for the "news" database

import datetime
import psycopg2

DBNAME = "news"


def connect(database_name):
    """Obtain database connection and cursor"""
    try:
        db = psycopg2.connect(database=database_name)
        cursor = db.cursor()
        return db, cursor
    except:
        print("Failed to connect to {}".format(database_name))


def get_top_three_articles():
    """Return most popular articles of all times in descending order"""
    db, cursor = connect(DBNAME)

    cursor.execute("select title, views from article_views \
               order by views desc limit 3;")

    return cursor.fetchall()
    db.close()


def get_most_pop_author():
    """Return most popular author of all times in descending order"""
    db, cursor = connect(DBNAME)

    cursor.execute("select t1.name, sum(t2.views) as views \
               from authors t1, article_views t2 \
               where t1.id = t2.author group by t1.name order by views desc")

    return cursor.fetchall()
    db.close()


def get_request_error_log():
    """Return a list of all days where more than '1%' of requests lead to
       errors"""
    db, cursor = connect(DBNAME)

    cursor.execute("select log_date, to_char(err_pct, '99.9') \
               from (select t1.log_date, t2.status_cnt * 100::numeric \
                     / (t1.status_cnt + t2.status_cnt) as err_pct \
                     from request_stat t1, request_stat t2 \
                     where t1.log_date = t2.log_date \
                     and t1.status = '200 OK' \
                     and t1.status != t2.status) as temp1 \
               where err_pct > 1")

    return cursor.fetchall()
    db.close()
