- Chạy file Snort_main.py để chạy api
- Config lại ip của server api trong line:
    app.run(debug=True)
    app.run(host='<ip máy>', port=<port được mở>, debug=True)
- Edit File api_func:   
    - Function Connect to DB:
        Cấu hình để connect đến DB postgres
            dbconnection = psycopg2.connect(user="<user kết nối với postgressql>", 
                                    password="", 
                                    host= "<ip của postgresDB server>", 
                                    port= "", 
                                    database="")                                    

    - Function Save Rule:
        Chỉnh lại path để save Rules vào folder của snort rule:
            name = "/etc/snort/rules/local.rules"
    - Function read Rule:
        Chỉnh lại path của file rule để đọc lưu vào DB
