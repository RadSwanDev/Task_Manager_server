const mysql = require("mysql2")

const db = mysql.createConnection({
    host : "localhost",
    user : "RadsDev",
    password : "belajar_sql123",
    database : "task_habi_system"
})

db.connect((error,success)=>{
    if(error){
        console.log("Failed to connect database")
    }

    console.log("success to connect database")
})

module.exports = db