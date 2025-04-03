const express = require("express")
const app = express()
const jwt = require("jsonwebtoken")
const port = 3000
const db = require("./db/db")
const bcrypt = require("bcryptjs")
const cors = require("cors")
const cookieParser = require("cookie-parser")
app.use(cors({
    origin: 'http://localhost:5173',
    credentials : true
}))
require("dotenv").config()

app.use(express.json())
app.use(cookieParser())
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

const formValidationRegister = (req,res,next)=>{
    const {password, email, username} = req.body
    const passwordRegex= /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/
    const emailRegex = /^[\w.-]+@[a-zA-Z\d.-]+\.[a-zA-Z]{2,}$/

    if (!username || !email || !password) {
        return res.status(400).send({
            message: "Username, email, and password are required!"
        });
    }


    if(!passwordRegex.test(password)){
        return res.status(400).send({
            message : "Password must have 8 character with an Uppercase,lowercase,numeric and special character."
        })
    }

    if(!password){
        return res.status(400).send({
            message : "Password required!"
        })
    }
    
    if(!email){
        return res.status(400).send({
            message : "Email is required!"
        })
    }

    if(!emailRegex.test(email)){
        return res.status(400).send({
            message : "email must have a character of '@'!."
        })
    }
    next()
}

app.post("/register",formValidationRegister,async (req,res)=>{
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
    res.header("Access-Control-Allow-Origin",'http://localhost:5173')
    try{
        const {username,password} = req.body;
        if(!username || !password){
            return res.status(400).send({
                message : "username and password field must been filled! "
            })
        }
      
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
           
            res.cookie('token',token,{
                httpOnly : true,
                maxAge : 24 * 60 * 60 * 1000,
                secure : false,
                sameSite : "strict"
            })

            res.send({
                token : token
            })
        })
    } catch(error){
        return res.status(500).send({status : "Internal server error",message : "something wrong try again"})       
    }
})

const authenticationValidation = (req,res,next)=>{
    const token = req.cookies.token
    if(!token){
        return res.status(403).send({message : "Invalid token!"})
    }
    try{
        const decode = jwt.verify(token,process.env.SECRET_KEY)
        req.user = decode;
        next()
    }catch(error){
        return res.status(401).send({message : "Unauthorized"})
    }

}

app.get("/dashboard",authenticationValidation,(req,res)=>{
    res.header("Access-Control-Allow-Origin",'http://localhost:5173')
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


app.get("/dashboard/profile",authenticationValidation,(req,res)=>{
    const userId = req.user.id
    db.query("SELECT * FROM profile WHERE user_id = ?",[userId],(error,result)=>{
        if(error){
            return res.status(400).send({error})
        }

        if(result){
            return res.status(200).send({
                message : "data find!",
                result  
            })
        }
    })
})

app.post("/dashboard/profile",authenticationValidation,(req,res)=>{
    const {telepon,tanggalLahir,jenisKelamin,fotoProfile} = req.body;
    const userId = req.user.id 
    db.query("UPDATE profile SET telepon =?,tanggal_lahir = ?,jenis_kelamin = ?,foto_profile = ? WHERE user_id = ?",
        [telepon,tanggalLahir,jenisKelamin,fotoProfile,userId],(error,result)=>{
            if(error){
                return res.status(400).send({
                    message : "Failed to update profile!",
                    error
                })
            }
            return res.status(200).send({
                message : "Success update the data",
                result
            })
        }
     )
})

 app.post("/logout",(req,res)=>{
    res.clearCookie("token",{
        httpOnly : true,
        secure : true,
        sameSite : "None"
    })

    res.status(200).send({
        status : "success",
        message : "Logged out success"
    })
 })

app.listen(port,()=>{
    console.log(`http://localhost:${port}`)
})
