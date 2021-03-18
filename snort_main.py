from flask import Flask
from flask_restful import Api, Resource
import api_func as apiFunc
import logging

app = Flask(__name__)
api = Api(app)

# logging.basicConfig(filename= "api.log",
#                     level=logging.DEBUG,
#                     format= f'%(levelname)s %(name)s %(threadName)s : %(message)s')

class snort_InsertDB(Resource): 
    def get(self):
        try:
            if (apiFunc.insertDB()):
                return {"data:": "Success insert to database!"}
            else:
                return {"data:": "Can not save to Database"}
        except:
            return {"data:": "Can not save to Database"}

    def post(self):
        try:
            if (apiFunc.insertDB()):
                return {"data:": "Success insert to database!"}
            else:
                return {"data:": "Can not save to Database!"}
        except:
            return {"data:": "Can not save to Database!"}

class snort_SaveRules(Resource):
    def get(self):
        try:
            if (apiFunc.saveToLocal()):
                apiFunc.restartSnort()
                return {"data:": "Success! and restart snort"} 
            else:
                return {"data:": "Can not save rules!"}
        except:
            return {"data:": "Can not save rules!"}

    def post(self):
        try:
            if (apiFunc.saveToLocal()):
                apiFunc.restartSnort()
                return {"data:": "Success!"}
            else:
                return {"data:": "Can not save rules!"}
        except:
            return {"data:": "Can not save rules!"}

class snort_restart(Resource):
    def post(self):
        apiFunc.restartSnort()


api.add_resource(snort_InsertDB, "/api/inserttodb")        
api.add_resource(snort_SaveRules, "/api/saverules")
# api.add_resource(snort_restart, "/api/restartsnort")


if __name__ == "__main__":
    app.run(debug=True)
