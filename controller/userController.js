const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

//registeration

exports.RegisterUser = async(req, res) =>{
    const {name,email,password} = req.body;
    try{
       
        const userExist = await User.findOne({email});
        if(userExist){
            return res.status(400).json({message:"the entered user already exist"});
        }
        
        
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password,salt);

        
        const user = await User.create({
            name,
            email,
            password: hashedPassword
        });
        
       

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET,{
            expiresIn : "1h"
        });

        res.status(201).json({
            token,
            user: { 
                id: user._id,
                name: user.name,
                email: user.email
            }
        })



    }catch(error){
        res.status(500).json({message:error.message})
    }
}

//login
exports.LoginUser = async(req, res) =>{
    const {email,password} = req.body;
    try{
        
        const user = await User.findOne({email});
        if(!user){
            return res.status(400).json({message:"invalid credentials"});
        }

        

        const isMatch  =await bcrypt.compare(password , user.password);
        if(!isMatch){
            return res.status(400).json({message:"invaild password"})
        }
        
       
        

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET,{
            expiresIn : "1h"
        });

        res.status(200).json({
            token,
            user: { 
                id: user._id,
                name: user.name,
                email: user.email
            }
        })



    }catch(error){
        res.status(500).json({message:error.message})
    }
}

const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
        user: process.env.EMAIL_USER,  
        pass: process.env.EMAIL_PASS,  
    },
});


exports.ForgotPassword = async (req, res) => {
    const { email } = req.body;
    try {
        
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        
        const resetToken = crypto.randomBytes(32).toString("hex");

        
        user.resetPasswordToken = crypto.createHash("sha256").update(resetToken).digest("hex");
        user.resetPasswordExpires = Date.now() + 3600000; 

        await user.save();

        
        const resetUrl = `http://localhost:3000/reset-password/${resetToken}`;
        const message = `
            <h1>Password Reset Request</h1>
            <p>Please click on the link below to reset your password</p>
            <a href=${resetUrl} clicktracking=off>${resetUrl}</a>
        `;

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: "Password Reset Request",
            html: message,
        });

        res.status(200).json({ message: "Email sent for password reset" });

    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};


exports.ResetPassword = async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    try {
       
        const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
        const user = await User.findOne({
            resetPasswordToken: hashedToken,
            resetPasswordExpires: { $gt: Date.now() },  
        });

        if (!user) {
            return res.status(400).json({ message: "Invalid or expired token" });
        }

        
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        await user.save();

        res.status(200).json({ message: "Password has been reset successfully" });

    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};