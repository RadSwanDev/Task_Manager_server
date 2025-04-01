const express = require("express")
const bodyParser = require("body-parser")
const app = express()
const jwt = require("jsonwebtoken")
const port = 3000
const db = require("./db/db")
const bcrypt = require("bcryptjs")
require("dotenv").config()

app.use(bodyParser.json())

app.get("/",(req,res)=>{
    try{
        db.query("SELECT * FROM authentication",(error,result)=>{
            if(error){
                const response = res.status(400).send({message : "Failed to sync data",error : error})
                return response
            }

            const response = res.status(200).send({status : "success fetching data",message : "success load the data", data : result})
            return response
        })
    }catch(error){
        return res.status(500).send({status : "Internal server error",message : "something wrong try again"})
    }
})


app.post("/register",async (req,res)=>{
    const {username,email,password} = req.body
    const hashedPassword = await bcrypt.hash(password,10)
    try{
        db.query("INSERT INTO authentication (username,email,password) VALUES (?, ?, ?)",[username,email,hashedPassword],(error,result)=>{
            if(error){
                const response = res.status(400).send({message : "Failed to sync data",error : error})
                return response
            }

            const response = res.status(200).send({
                message : "success register as an use our website!",
                data : {
                    username : username,
                    email :email
                }    
            })
            return response

        })
    } catch(error){
        return res.status(500).send({status : "Internal server error",message : "something wrong try again"})       
    }
})


app.post("/login",(req,res)=>{
    try{
        const {username,password} = req.body;
        db.query("SELECT * FROM authentication WHERE username = ?",[username],async(error,result)=>{
            if(error || result.length === 0){
                const response = res.status(400).send({
                    status : "Bad Request!",
                    message : "Failed to login, the username not listed on our system"
                })
                return response
            }

            const user = result[0]
            const isMatch = await bcrypt.compare(password,user.password)
            if(!isMatch){
                const response = res.status(400).send({
                    status : "Invalid fill!",
                    message : "Failed to login, the password is wrong"    
                })
                return response
            }
            const token = jwt.sign({
                id : user.id,
                username : user.username,
                email : user.email
            },process.env.SECRET_KEY,{expiresIn : "24h"})
           
            res.send({
                token : token
            })
        })
    } catch(error){
        return res.status(500).send({status : "Internal server error",message : "something wrong try again"})       
    }
})

const authenticationValidation = (req,res,next)=>{
    const autHeader = req.headers['authorization']
    if(!autHeader || !autHeader.startsWith("Bearer ")){
        return res.status(403).send({message : "Invalid Token"})
    }

    const token = autHeader.split(" ")[1];
    try{
        const decode = jwt.verify(token,process.env.SECRET_KEY)
        req.user = decode;
        next()
    }catch(error){
        return res.status(401).send({message : "Unauthorized"})
    }
}

app.get("/dashboard",authenticationValidation,(req,res)=>{
    res.send({message : `hello ${req.user.username}, welcome back!`})
})

app.listen(port,()=>{
    console.log(`http://localhost:${port}`)
})