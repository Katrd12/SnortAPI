from flask import Flask
from flask_restful import Api, Resource
import api_func as apiFunc

app = Flask(__name__)
api = Api(app)
    
class snort_InsertDB(Resource): 
    def get(self):
        apiFunc.insertDB()
        
            
        
api.add_resource(snort_InsertDB, "/savetodb")        


if __name__ == "__main__":
    app.run(debug=True)
