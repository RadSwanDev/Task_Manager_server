const express = require("express")
const app = express()
const jwt = require("jsonwebtoken")
const port = 3000
const db = require("./db/db")
const bcrypt = require("bcryptjs")
require("dotenv").config()

app.use(express.json())

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
        const decode = jwt.verify(token,process.env.SECRET_KEY)
        req.user = decode;
        next()
}

app.get("/dashboard",authenticationValidation,(req,res)=>{
    const userId = req.user.id
    db.query(`
        SELECT tasks.id, tasks.title, tasks.description, tasks.status, tasks.created_at, tasks.updated_at FROM tasks JOIN authentication ON tasks.user_id = authentication.id WHERE authentication.id = ? `,[userId],
    (error,result)=>{
        if(error){
            return res.status(400).send({message : "Failed to fetch tasks",error})
        }
        return res.status(200).send({message : "success fetching data",data : result})
    })
})

app.post("/dashboard/add",authenticationValidation,(req,res)=>{
    const userId = req.user.id;
    const {title,description,status} = req.body
    const created_at = new Date();
    const updated_at = new Date();

    db.query(`
        INSERT INTO tasks(title,description,status,created_at,updated_at,user_id) VALUES (?, ?, ?, ?, ?,?)
        `,[title,description,status,created_at,updated_at,userId],(error,result) =>{
            if(error){
                return res.status(400).send({message : "Failed to add task",error:error})
            }
            return res.status(201).send({
                message : "Task successfully added!",
                data : {
                    id : result.insertId,
                    title, 
                    description,
                    status,
                    created_at,
                    updated_at,
                    user_id : userId
                }
            })
        }

    )
 })

 app.delete("/dashboard/delete",authenticationValidation,(req,res)=>{
    const userId = req.user.id
    const {id} = req.body

    db.query('DELETE FROM tasks WHERE id = ? AND user_id = ?',[id,userId],(error,result)=>{
        if(error){
            return res.status(400).send({message : "Failed to delete task"})
        }
        if(result.affectedRows === 0){
            return res.status(404).send({message : "Task not found!"})
        }
        return res.status(200).send({message : "Tasks successfully deleted"})
    })
 })

app.listen(port,()=>{
    console.log(`http://localhost:${port}`)
})
