import os
import psycopg2
from config import DATABASE_USER, DATABASE_PASSWORD

def get_db_connection(database_name):
    return psycopg2.connect(
        dbname=database_name,
        user=DATABASE_USER,
        password=DATABASE_PASSWORD,
        host="localhost",
        port="5432"
    )