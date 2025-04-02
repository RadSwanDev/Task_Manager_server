const mysql = require("mysql2")
require("dotenv").config()
const db = mysql.createConnection({
    host : process.env.HOST_DATABASE,
    user : process.env.USERNAME_DATABASE,
    password : process.env.PASSWORD_DATABASE,
    database : process.env.USE_DATABASE
})

db.connect((error,success)=>{
    if(error){
        console.log("Failed to connect database")
    }

    console.log("success to connect database")
})

module.exports = db