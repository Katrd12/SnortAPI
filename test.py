# import requests
import psycopg2
from psycopg2 import Error

# BASE = "http://127.0.0.1:5000/"

# response = requests.get(BASE + "rules")
# print(response.json())

try:
    connection = psycopg2.connect(user="postgres", 
                                password="se130090", 
                                host= "10.10.2.6", 
                                port= "5432", 
                                database="snort")
    cursor = connection.cursor()
    cursor.execute("Select version()")
    record = cursor.fetchone()
    print ("Youre connect to - ", record, "\n")
    cursor.execute("Select * from data")
    record = cursor.fetchall()
    print ("Youre connect to - ", record, "\n")

except (Exception, Error) as error:
    print("Error while connecting to PostgreSQL", error)

finally:
    if(connection):
        cursor.close()
        connection.close()
        print ("Postgres connection is cloesed")