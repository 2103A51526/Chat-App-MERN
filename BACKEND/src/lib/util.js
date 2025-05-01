import jwt from "jsonwebtoken"

export const generateToken= (userId, res) =>{
    const token = jwt.sign({userId}, process.env.JWT_SECRET,{
        expiresIn:"5h"
    })
    res.cookie("jwt", token, {
        maxAge: 5*60,
        httpOnly: true, //prevent xss cross-site attack
        sameSite: "strict", //csrf attack cross-site request forgery attack\
        secure: process.env.NODE_ENV !=="development",
    });
    return token;

} 