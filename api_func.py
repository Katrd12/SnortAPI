import psycopg2
from psycopg2 import Error
import subprocess
from datetime import datetime
import time

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
    dbconnection = psycopg2.connect(user="snort", 
                                    password="123qweaA@", 
                                    host= "10.0.3.3", 
                                    port= "5432", 
                                    database="snort")                                    
    return dbconnection

def emptyDatabase():
    try:        
        dbConnect = dbConnection()
        cursor = dbConnect.cursor()
        sql = 'delete from snort_rules'
        cursor.execute(sql)
        dbConnect.commit()
    except (Exception, Error) as error:
        print(f"Error while connecting to PostgreSQL: {error}")
    finally:
        if (dbConnect):
            cursor.close()
            dbConnect.close()


## nối chuỗi
def catRule(rOption):
    cRule = " " . join(str(val) for x, val in rule_d.items()) + " " + rOption
    return cRule
    
def readRule():
    #name = 'snort3-community.rules'
    name = "/etc/snort/rules/local.rules"
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
    result = False
    try:        
        dbConnect = dbConnection()
        cursor = dbConnect.cursor()
        sql = 'select status, action, protocol, src_address, src_port, direction, dest_address, dest_port, options from snort_rules'
        cursor.execute(sql)
        rules_input = cursor.fetchall()
        #print(rules_input)
        if (len(rules_input) != 0):
            rules = []
            for line in rules_input:
                h_pos = 0
                for x in rule_d:
                    rule_d[x] = line[h_pos]
                    h_pos += 1
                    if (h_pos == 7):
                        rule_opt = line[h_pos+1]
                if (rule_d["Status"] == False):
                    rule_d["Status"] = "#"
                elif (rule_d["Status"] == True):
                    rule_d["Status"] = ""
                rule = catRule(rule_opt)
                rules.append(rule)
            name = "/etc/snort/rules/local.rules"
            fh = open(name, 'w')
            for line in rules:
                fh.write(line.strip() + "\n")
            fh.close()
            result = True        
        else:
            print("Database is empty!")
        return result
            
    except (Exception, Error) as error:
        print(f"Error while connecting to PostgreSQL: {error}")
        return result
    
    finally:
        if (dbConnect):
            cursor.close()
            dbConnect.close()

## add vao database    
def insertDB():
    result = False
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
            sql = f'''insert into snort_rules (action, protocol, src_address, src_port, direction, dest_address, dest_port, options, status,created_at,updated_at)
                    values 
                    ('{rule_d["Action"]}', '{rule_d["Proto"]}', '{rule_d["IpSrc"]}', '{rule_d["PortSrc"]}', '{rule_d["Operation"]}', '{rule_d["IpDes"]}', '{rule_d["PortDes"]}', '{rOption()}', '{rule_d["Status"]}','%s','%s')''' % (datetime.today().strftime('%d/%m/%y'),datetime.today().strftime('%d/%m/%y'))  
            #print(sql)
            cursor.execute(sql)
            dbConnect.commit()
        result = True
        return result
    except (Exception, Error) as error:
        print(f"Error while connecting to PostgreSQL: {error}")
        return result

    finally:
        if (dbConnect):
            cursor.close()
            dbConnect.close()

## restart snort
def restartSnort():
    try:
        subprocess.run(["systemctl", "restart", "snort"], capture_output=True)
        time.sleep(0.5)
        subprocess.run(["systemctl", "restart", "barnyard2"], capture_output=True)
    except (Exception, Error) as error:
        print(f"Error while running command: {error}")


