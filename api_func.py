import psycopg2
from psycopg2 import Error
import subprocess

# BASE = "http://127.0.0.1:5000/"

# response = requests.get(BASE + "rules")
# print(response.json())

rule_d ={
    'Status': "",
    'Action': "",
    'Proto': "",
    'IpSrc': "",
    'PortSrc': "",
    'Operation': "",
    'IpDes': "",
    'PortDes': "",
        }

def dbConnection():
    dbconnection = psycopg2.connect(user="postgres", 
                                    password="se130090", 
                                    host= "10.10.2.6", 
                                    port= "5432", 
                                    database="snort")                                    
    return dbconnection

## nối chuỗi
def catRule(rOption):
    cRule = " " . join(str(val) for x, val in rule_d.items()) + " " + rOption
    return cRule
    
def readRule():
    name = 'snort3-community.rules'
    # name = "local.rule"
    fh = open(name)
    rules = []
    for line in fh:
        rules.append(line)
    return rules
## Cắt chuỗi
def splitString(iString):
    def sHeader():        
        header = iString[:iString.find("(")].rstrip().split(" ")
        if (len(header) != 8):
            header.insert(0, " ")
        return header
    def sOption():
        option = iString[iString.find("("):]
        return option
    return sHeader, sOption

def saveToLocal():
    try:
        dbConnect = dbConnection()
        cursor = dbConnect.cursor()
        sql = 'select status, action, protocol, ip_src, port_src, direction, ip_des, port_des, rule_option from snort_rule'
        cursor.execute(sql)
        rules_input = cursor.fetchall()
        if len(rules_input) != 0:
            rules = []
            for line in rules_input:
                h_pos = 0
                for x in rule_d:
                    rule_d[x] = line[h_pos]
                    h_pos += 1
                    if h_pos == 7:
                        rule_opt = line[h_pos+1]
                if (rule_d["Status"] == False):
                    rule_d["Status"] = "#"
                elif (rule_d["Status"] == True):
                    rule_d["Status"] = ""
                rule = catRule(rule_opt)
                rules.append(rule)
            print(rules[0]) 
            name = "local.rule"
            fh = open(name, 'w+')
            for line in rules:
                fh.write(line)
            fh.close()
        else:
            print("Database is empty!")
            
    except (Exception, Error) as error:
        print(f"Error while connecting to PostgreSQL: {error}")
    
    finally:
        if (dbConnect):
            cursor.close()
            dbConnect.close()

## add vao database    
def insertDB():
    try:
        dbConnect = dbConnection()
        cursor = dbConnect.cursor()
        rules = readRule()
        for line in rules:
            rule = line
            rHeader, rOption = splitString(rule)
            h_pos = 0
            for x in rule_d:
                rule_d[x] = rHeader()[h_pos]
                h_pos += 1
            if (rule[0] == '#'):
                rule_d["Status"] = False
            else:
                rule_d["Status"] = True
            sql = f'''insert into snort_rule (action, protocol, ip_src, port_src, direction, ip_des, port_des, rule_option, status)
                    values 
                    ('{rule_d["Action"]}', '{rule_d["Proto"]}', '{rule_d["IpSrc"]}', '{rule_d["PortSrc"]}', '{rule_d["Operation"]}', '{rule_d["IpDes"]}', '{rule_d["PortDes"]}', '{rOption()}', '{rule_d["Status"]}')'''  
            cursor.execute(sql)
            dbConnect.commit()

    except (Exception, Error) as error:
        print(f"Error while connecting to PostgreSQL: {error}")

    finally:
        if (dbConnect):
            cursor.close()
            dbConnect.close()

## restart snort
def restartSnort():
    try:
        subprocess.run(["systemctl", "restart", "snort"], capture_output=True)
    except (Exception, Error) as error:
        print(f"Error while running command: {error}")