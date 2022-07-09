const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
app.use(express.json())
const users=[{
	id:"1",
	username:"amit",
	password:"Amit@2001",
	isAdmin:true
},
{
	id:"2",
	username:"ajay",
	password:"Ajay@2001",
	isAdmin:false
}
]
// after logout will delete these refreshtokens

let refreshTokens = []
app.post("/api/refresh",(req,res)=>{
     //take refresh token from user 
     const refreshToken  = req.body.token;

     // send error if no token or invalid
     if(!refreshToken){
     	return res.status(401).json("You are not authenticated!!")
     }
     if(!refreshTokens.includes(refreshToken)){
     	return res.status(403).json("Not token")
     }
     jwt.verify(refreshToken,"myrefreshsecretkey",(err,user)=>{
     	if(err){
     		console.log("error in token")
     	}
     	else{
     		refreshTokens = refreshTokens.filter((token)=> token!== refreshToken)
     	    const newAccessToken = generateAccessToken(user)
     	    const newRefreshToken = generateRefreshToken(user)
     	    refreshTokens.push(newRefreshToken);
     	    res.status(200).json({
     	    	accessToken:newAccessToken,
     	    	refreshToken:newRefreshToken
     	    })
     	}
     })
     //if everything is ok, create new token
})
const generateAccessToken = (user)=>{
	return jwt.sign({id:user.id,isAdmin:user.isAdmin},"mysecretkey",{expiresIn:"10m"})
	   
}
const generateRefreshToken = (user)=>{
	return  jwt.sign({id:user.id,isAdmin:user.isAdmin},"myrefreshsecretkey")
}
app.post('/api/login',(req,res)=>{
	const {username,password} = req.body;
	// finding user with given username and password
	const user = users.find((u)=>{
      return u.username===username && u.password===password
	})
	if(user){
		//generate an access token when a request is send
	 const accessToken =   generateAccessToken(user)
	  const refreshToken = generateRefreshToken(user)
	   refreshTokens.push(refreshToken)
	   res.json({
	   	username:user.username,
	   	isAdmin:user.isAdmin,
	   	accessToken,
	   	refreshToken //generate a token in user side
	   })
	}
	else{
		res.status(400).json("Username or password incorrect")
	}
	
})
const verify = (req,res,next)=>{
	// user can send access token thorugh headers with authorization as key and accesstoken as value
   // write Bearer before accessToken in value
	const authHeader = req.headers.authorization
   if(authHeader){
   const token = authHeader.split(" ")[1]; // remember we have written Bearer in value so splitting up
   jwt.verify(token,"mysecretkey",(err,user)=>{
   	if(err){
   		return res.status(403).json("Token is not valid")
   	}
   	else{
   		req.user =  user;
   		next();
   	}
   })
   }
   else{
    res.status(400).json("Error Occurs")
   }
}
app.post("/api/logout",verify,(req,res,next)=>{
	const refreshToken = req.body.token;
	refreshTokens =  refreshTokens.filter((token)=>token!==refreshToken);
	res.status(200).json("You have logged out succesfully")
})
app.delete("/api/users/:id",verify,(req,res)=>{
	if(req.user.id===req.params.id || req.user.isAdmin){
		res.status(200).json("User Has Been deleted")
	}
	else{
		res.status(400).json("Can't delete")
	}
})
app.listen(5000,()=>{
	console.log('Backend Server is Running...')
})