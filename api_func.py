# import requests
import psycopg2
from psycopg2 import Error

# BASE = "http://127.0.0.1:5000/"

# response = requests.get(BASE + "rules")
# print(response.json())


# name = 'snort3-community.rules'
name = "local.rule"
fh = open(name)
rules = []
for line in fh:
    rules.append(line)
# r_pos = 0
# rule = rules[r_pos]
# print(rules[r_pos])
# header = rule[:rule.find("(")].rstrip().split(" ")
# option = rule[rule.find("("):]
rule_d = {
    'Status': "",
    'Action': "",
    'Proto': "",
    'IpSrc': "",
    'PortSrc': "",
    'Operation': "",
    'IpDes': "",
    'PortDes': "",
        }
# h_pos = 0
# for x in rule_d:
#     rule_d[x] = header[h_pos]
#     h_pos += 1
# print(rule_d)
# # rules.pop(r_pos)
# # print(rules[0])
# # rule_d["Status"] = ""
# # rule_d["Action"] = ""

## nối chuỗi
# rules[r_pos] =" " . join(str(val) for x, val in rule_d.items()) + " " + option
# print(rules[r_pos])


# add vao database
try:
    connection = psycopg2.connect(user="postgres", 
                                password="se130090", 
                                host= "10.10.2.6", 
                                port= "5432", 
                                database="snort")
    cursor = connection.cursor()
#     cursor.execute('select status, action, protocol, ip_src, port_src, direction, ip_des, port_des, rule_option from snort_rule')
#     rules_input = cursor.fetchall()
#     if len(rules_input) != 0:
#         rules = []
#         for line in rules_input:
#             h_pos = 0
#             for x in rule_d:
#                 rule_d[x] = line[h_pos]
#                 h_pos += 1
#                 if h_pos == 7 :
#                     rule_opt = line[h_pos+1]
#             if (rule_d["Status"] == False):
#                 rule_d["Status"] = "#"
#             elif (rule_d["Status"] == True):
#                 rule_d["Status"] = ""
#             print(rule_d["Status"])
#             rule = " " . join(str(val) for x, val in rule_d.items()) + " " + rule_opt
#             rules.append(rule)
#         print(rules[0]) 
#         name = "local.rule"
#         fh = open(name, 'w+')
#         for line in rules:
#             fh.write(line)
#         fh.close()
#     else:
#         print("Database is empty!")

    for line in rules:
        rule = line
        header = rule[:rule.find("(")].rstrip().split(" ")
        if (len(header) != 8):
            header.insert(0, " ")
        option = rule[rule.find("("):]
        h_pos = 0
        for x in rule_d:
            rule_d[x] = header[h_pos]
            h_pos += 1
        if (rule[0] == '#'):
            rule_d["Status"] = False
        else:
            rule_d["Status"] = True
        cursor.execute(f'''insert into snort_rule (action, protocol, ip_src, port_src, direction, ip_des, port_des, rule_option, status)
                        values 
                        ('{rule_d["Action"]}', '{rule_d["Proto"]}', '{rule_d["IpSrc"]}', '{rule_d["PortSrc"]}', '{rule_d["Operation"]}', '{rule_d["IpDes"]}', '{rule_d["PortDes"]}', '{option}', '{rule_d["Status"]}')'''
                        )
        connection.commit()

                

except (Exception, Error) as error:
    print("Error while connecting to PostgreSQL:", error)

finally:
    if(connection):
        cursor.close()
        connection.close()
        print ("Postgres connection is cloesed")

