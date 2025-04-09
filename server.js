const express = require("express")
const app = express()
const jwt = require("jsonwebtoken")
const port = 3000
const bcrypt = require("bcryptjs")
// const cors = require("cors")
const cookieParser = require("cookie-parser")
const {google} = require("googleapis")
const supabase = require("./db/db")
// OauthConfiguration
// const oauth2Client = new google.auth.OAuth2(
//     process.env.GOOGLE_CLIENT_ID, 
//     process.env.GOOGLE_CLIENT_SECRET,
//     "http://localhost:3000/auth/google/callback"
// )


// const scopes = [
//     "https://www.googleapis.com/auth/userinfo.email",
//     "https://www.googleapis.com/auth/userinfo.profile"
// ]


// const authorizaionURL = oauth2Client.generateAuthUrl({
//     access_type : "offline",
//     scope : scopes,
//     include_granted_scopes : true
// })


// app.get("/auth/google",(req,res)=>{
//     res.redirect(authorizaionURL)
// })

// app.get("/auth/google/callback",async (req,res)=>{
//     try{
//     const {code} = req.query

//     const {tokens} = await oauth2Client.getToken(code)
//     oauth2Client.setCredentials(tokens)

//     const oauth2 = google.oauth2({
//         auth : oauth2Client,
//         version : "v2",
//     })

//     const {data} = await oauth2.userinfo.get();
//     if(!data || !data.email){
//         return express.json({
//             data : data,
//         })
//     }
//     const email = data.email;
//     const username = data.name
   


//     db.query("SELECT * FROM authentication WHERE email = ?",[email],async(error,results)=>{
//         if(error){
//             return res.status(500).send({message : "Database error",error : error})
//         }

//         let user
//         if(results.length === 0){
//             user = db.query("INSERT INTO authentication (username, email,password) VALUES (?, ?,?)",
//             [username,email,""],
//             (insertError,insertResult)=>{
//                 if(insertError){
//                     return res.status(500).send({message : "Failed to insert account"})
//                 }
            
//             user ={
//                 id : insertResult.insertId,
//                 username,
//                 email
//             }
            
//             const token = jwt.sign(user, process.env.SECRET_KEY,{expiresIn :"24h" })

//             res.cookie("token",token,{
//                 httpOnly : true,
//                 maxAge : 24 * 60 * 60 * 1000,
//                 secure : false,
//                 sameSite : "strict"          
//              })
//             return res.redirect("http://localhost:5173/dashboard")
//             }
//             )
//         }else{
//             user = results[0]
//             const token = jwt.sign({
//                 id : user.id,
//                 username : user.username,
//                 email : user.email,
//             },process.env.SECRET_KEY, {expiresIn : "24h"})
            
//             res.cookie("token",token,{
//                 httpOnly : true,
//                 maxAge: 24 * 60 * 60 * 1000,
//                 secure : false,
//                 sameSite : "strict"
//             })
//             return res.redirect("http://localhost:5173/dashboard")
//         }
//     })
//     }catch(error){
//         return res.status(500).send({message : "Internal server error",error})
//     }
// })


// app.use(cors({
//     origin: 'http://localhost:5173',
//     credentials : true
// }))
// const session = require("express-session")
// const passport = require("passport")
require("dotenv").config()

// middleware
app.use(express.json())
app.use(cookieParser())

// app.use(session({
//     secret : process.env.SECRET_KEY,
//     resave : false,
//     saveUninitialized : true
// }))


// route
app.get("/",async (req,res)=>{
try{
    const {data,error} = await supabase
    .from("authentication")
    .select("*")

    if(error){
        return res.status(500).send({message : "Failed"})
    }

    if(data.length === 0){
        return res.status(404).send({users : "users not found! its empty lets add it"})
    }

    return res.status(200).send({message : "users list",data:data})
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
    if(!username || !email || !password){
        return res.status(400).send({status : "Bad Request!"})
    }
    const hashedPassword = await bcrypt.hash(password,10)
    try{
        const {data,error} = await supabase
        .from("authentication")
        .insert({username,email,password : hashedPassword})
        .select()
        console.log(error)
        console.log(data)
        if(error){
            res.status(400).send({status : "bad request",error : error})
        }

        return res.status(200).send({status : "Register completed!",data})
    } catch(error){
        return res.status(500).send({status : "Internal server error",message : "something wrong try again"})       
    }
})

app.post("/login",async (req,res)=>{
    res.header("Access-Control-Allow-Origin",'http://localhost:5173')
    try{
        const {username,password} = req.body;
        if(!username || !password){
            return res.status(400).send({
                message : "username and password field must been filled! "
            })
        }
      
        const {data,error} = await supabase 
        .from('authentication')
        .select("*")
        .eq("username",username)
        .single()

        if(error || !data){
            return res.status(401).send({message : "Invalid username or pasword"})
        }
        
        const isMatch = await bcrypt.compare(password, data.password)
        if(!isMatch){
            return res.status(401).send({message : "Pasword not match Invalid!"})
        }
        const token = jwt.sign({
                id : data.id,
                username : data.username,
                email : data.email
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
        }catch(error){
        return res.status(500).send({status : "Internal server error",message : "something wrong try again",error})       
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




app.get("/dashboard",authenticationValidation,async (req,res)=>{
    try{


    const userId = req.user.id
    const {data,error} = await supabase
    .from("tasks")
    .select("*")
    .eq("user_id",userId)

    if(error){
        return res.status(500).send({
            message : "Failed to fetch tasks",
            error
        })
    }
    return res.status(200).send({message : "sucesssfully fetched tasks",data})
    }catch(error){
        return res.status(500).send({
            message : "failed to fetch task",
            error
        })
    }
})

app.post("/dashboard/add",authenticationValidation,async (req,res)=>{
    const userId = req.user.id;
    const {title,description,status} = req.body
    const created_at = new Date();
    const updated_at = new Date();

    const {data,error} = await supabase
    .from("tasks")
    .insert([{title,description,status,created_at,updated_at,user_id : userId}])
    .select() 

    if(error){
        return res.status(400).send({message : "Failed to add tasks",error})
    }

    return res.status(201).send({
        message : "task successfully added!",
        data : data[0]
    })
 })

 app.get("/dashboard/task/:id",authenticationValidation,async (req,res)=>{
    const id = req.params.id
    const useId = req.user.id

    const {data,error} = await supabase
    .from("tasks")
    .select("*")
    .eq("id",id)
    .eq("user_id",useId)
    
    if(error){
        return res.status(400).send({message : "Failed load task!",error})
    }

    return res.status(200).send({message : "Success load the task!",data})
 })

 app.put("/dashboard/edit/:id", authenticationValidation, async (req, res) => {
    const id = req.params.id;
    const { title, description, status } = req.body;
    const updatedAt = new Date();
    const userId = req.user.id;
  
    const { data, error } = await supabase
      .from("tasks")
      .update({
        title,
        description,
        status,
        updated_at: updatedAt
      })
      .eq("id", id)
      .eq("user_id", userId)
      .select();
  
    if (error) {
      console.error("Error updating task:", error); 
      return res.status(400).send({ message: "Failed to update task", error });
    }
  
    if (!data || data.length === 0) {
      return res.status(404).send({ message: "Task not found or not authorized" });
    }
  
    return res.status(200).send({
      message: "Task updated successfully",
      data: data[0]
    });
  });
  
app.patch("/dashboard/task/status/in-progress/:id",authenticationValidation,async (req,res)=>{
    try{
        const id = req.params.id
        const userId = req.user.id
        const status = "In-progress"
        const updateAt = new Date()
   
        const {data,error} = await supabase
       .from("tasks")
       .update({
           updated_at :updateAt,
           status
       })
       .eq("id",id)
       .eq("user_id",userId)
   
        if(error){
            return res.status(400).send({message : "Failed to change status",error})
        }
        
        return res.status(200).send({message : "Successfully to change status",data})
   }catch(error){
        return res.status(500).send({message : "Error change the status",error})
       }
        
})

app.patch("/dashboard/task/status/success/:id",authenticationValidation,async(req,res)=>{
    try{
        const id = req.params.id
        const userId = req.user.id
        const status = "Success"
        const updateAt = new Date()
    
        const {data,error} = await supabase
        .from("tasks")
        .update({
            updated_at :updateAt,
            status
        })
        .eq("id",id)
        .eq("user_id",userId)
    
        if(error){
            return res.status(400).send({message : "Failed to change status",error})
        }
    
        return res.status(200).send({message : "Successfully to change status",data})
       }catch(error){
        return res.status(500).send({message : "Error change the status",error})
       }
})

app.patch("/dashboard/task/status/pending/:id",authenticationValidation,async (req,res)=>{
   try{
    const id = req.params.id
    const userId = req.user.id
    const status = "Pending"
    const updateAt = new Date()

    const {data,error} = await supabase
    .from("tasks")
    .update({
        updated_at :updateAt,
        status
    })
    .eq("id",id)
    .eq("user_id",userId)

    if(error){
        return res.status(400).send({message : "Failed to change status",error})
    }

    return res.status(200).send({message : "Successfully to change status",data})
   }catch(error){
    return res.status(500).send({message : "Error change the status",error})
   }
})


 app.delete("/dashboard/delete/:id",authenticationValidation, async (req,res)=>{
    const userId = req.user.id
    const id = req.params.id
    
    const {data,error} = await supabase
    .from("tasks")
    .delete()
    .eq("id",id)
    .eq("user_id",userId)

    if (error) {
        return res.status(400).send({ message: "Failed to delete task", error });
      }
    
    if (!data || data.length === 0) {
        return res.status(404).send({ message: "Task not found!" });
    }
    
      return res.status(200).send({ message: "Task successfully deleted", data });
    })


app.get("/dashboard/profile",authenticationValidation,async (req,res)=>{
    const userId = req.user.id

    const {data,error} = await supabase
    .from("profile")
    .select("*")
    .eq("user_id",userId)

    if(error){
        return res.status(400).send({status : "bad request"})
    }

    return res.status(200).send({message : "Successfully",data})

})

app.put("/dashboard/profile",authenticationValidation,async (req,res)=>{
    const {telepon,tanggalLahir,jenisKelamin,fotoProfile} = req.body;
    const userId = req.user.id 
 
    const {data,error} = await supabase
    .from("profile")
    .update({
        telepon,
        "tanggal_lahir":tanggalLahir,
        "jenis_kelamin":jenisKelamin,
        "foto_profile":fotoProfile})
    .eq("user_id",userId)
    .select()

    if(error){
        return res.status(400).send({message : "Failed to change data"})
    }

    return res.status(200).send({message : "Successfully data changed",data})
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
