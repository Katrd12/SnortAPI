from flask import Flask
from flask_restful import Api, Resource
import psycopg2 
from psycopg2 import Error

app = Flask(__name__)
api = Api(app)
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
    
class snort_Function(Resource): 
    def get(self):
        name = "snort3-community.rules"
        fh = open(name, 'r')
        rules = []
        for line in fh: 
            rules.append(line)
        fh.close()
        return {"data": rules}
        
            
        
api.add_resource(snort_Function, "/rules")        
    # def add_Rule():
    #     name = "snort3-community.rules"
    #     fh = open(name, 'a')
    
# r_pos = 0
# rule = rules[r_pos]
# print(rules[r_pos])
# header = rule[:rule.find("(")].rstrip().split(" ")
# option = rule[rule.find("("):]
# rule_d = {
#     'Status': "",
#     'Action': "",
#     'Proto': "",
#     'IpSrc': "",
#     'PortSrc': "",
#     'Operation': "",
#     'IpDes': "",
#     'PortDes': "",
#         }
# h_pos = 0
# for x in rule_d:
#     rule_d[x] = header[h_pos]
#     h_pos += 1
# rules.pop(r_pos)
# print(rules[0])
# rule_d["Status"] = ""
# rule_d["Action"] = ""
# rules[r_pos] =" " . join(str(val) for x, val in rule_d.items()) + " " + option
# print(rules[r_pos])
# fh = open(name, 'w')
# for rule in rules:
#     fh.write(rule)
# print(option)

## Add Rule to addbase

# try:
#     connection = psycopg2.connect(user="postgres", 
#                                 password="se130090", 
#                                 host= "10.10.2.6", 
#                                 port= "5432", 
#                                 database="snort")
#     cursor = connection.cursor()
#     for line in rules:
#         rule = line
#         header = rule[:rule.find("(")].rstrip().split(" ")
#         if (len(header) != 8):
#             header.insert(0, " ")
#         option = rule[rule.find("("):]
#         h_pos = 0
#         for x in rule_d:
#             rule_d[x] = header[h_pos]
#             h_pos += 1
#         if (rule[0] == '#'):
#             rule_d["Status"] = 0
#             cursor.execute(f'''insert into snort_rule (action, protocol, ip_src, port_src, direction, ip_des, port_des, rule_option, status)
#                             values 
#                             ('{rule_d["Action"]}', '{rule_d["Proto"]}', '{rule_d["IpSrc"]}', '{rule_d["PortSrc"]}', '{rule_d["Operation"]}', '{rule_d["IpDes"]}', '{rule_d["PortDes"]}', '{option}', '{rule_d["Status"]}')'''
#                             )
#             connection.commit()
#         else:
#             rule_d["Status"] = 1
#             cursor.execute(f'''insert into snort_rule (action, protocol, ip_src, port_src, direction, ip_des, port_des, rule_option, status)
#                             values 
#                             ('{rule_d["Action"]}', '{rule_d["Proto"]}', '{rule_d["IpSrc"]}', '{rule_d["PortSrc"]}', '{rule_d["Operation"]}', '{rule_d["IpDes"]}', '{rule_d["PortDes"]}', '{option}', '{rule_d["Status"]}')'''
#                             )
#             connection.commit()


if __name__ == "__main__":
    app.run(debug=True)
