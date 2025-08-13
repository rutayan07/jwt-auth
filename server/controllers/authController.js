import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import {response} from 'express';
import { transporter } from '../config/nodemailer.js';
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from '../config/emailTemplates.js';

export const register = async (req, res) =>{
    const {name, email, password} = req.body;

    if(!name || !email || !password){
        return res.json({success: false, message: "Missing Details"})
    }

    try {

        const existingUser = await userModel.findOne({email})

        if(existingUser){
            return res.json({ sucess: false, message: "User already exists"});
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new userModel({name, email, password: hashedPassword});
        await user.save();

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, { expiresIn: '7d'});
        
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict', 
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        //sending welcome email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: `Welcome to EdenX: ${name}`,
            text: `Welcome to EdenX website. Your account has been
            created with email id: ${email}`
        }

        await transporter.sendMail(mailOptions);

        return res.json({success: true});

    } catch (error) { 
        res.json({sucess: false, message: error.message})
        
    }
} 

export const login = async (req, res)=>{
    const {email, password} = req.body;

    if(!email || !password){
        return res.json({success: false, message: 'Email and password are required'}) 
    }
    try {

        const user = await userModel.findOne({email});

        if(!user){
            return res.json({success: false, message: 'Invalid email'})
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if(!isMatch){
            return res.json({success: false, message: 'Invalid Password'})
        }
        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, { expiresIn: '7d'});
        
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict', 
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.json({success: true, message: 'OTP sent succesfully'});

    } catch (error) {

        return res.json({success: false, message: 'Email and password are required'}) 

    }

} 

export const logout = async(req, res)=>{
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 
            'none' : 'strict', 
        })

        return res.json({sucess: true, message: "Logged Out"})
    } catch (error) {
        return res.json({ sucess: false, message: error.message})
        
    }
}
//send verification otp to username
export const sendverifyOtp = async(req, res)=>{
    try {

        const {userId} = req.body;

        const user = await userModel.findById(userId);

        if(user.isAccountVerified){
            res.json({success: false, message: "Account already verified"})
        }
        
         const otp = String(Math.floor(100000 + Math.random() * 900000))
 
         user.verifyOtp = otp;
         user.verifyOtpExpiredAt = Date.now() + 24 * 60 * 60 * 1000

         await user.save();

         const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account verification OTP',
           // text: `Your OTP is ${otp}. Verify your account using this OTP.`,
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", 
                user.email)
         }
         await transporter.sendMail(mailOption);

         res.json({success: true,  message: 'Verification OTP Sent on Email'});

    } catch (error) {
        res.json({ success: false, message: error.message});
        
    }
}

export const verifyEmail = async (req, res)=>{
    const {userId, otp} = req.body;

    if(!userId || !otp){
        return res.json({sucess: false, message: 'Missing Details'});
    }

    try {
        const user = await userModel.findById(userId);

        if(!user){
            return res.json({success: false, message: 'User Not Found'});
        }

        if(user.verifyOtp === '' || user.verifyOtp !== otp){
            return res.json({sucess: false, message: 'Invalid OTP'});
        }

        if(user.verifyOtpExpiredAt < Date.now()){
            return res.json({sucess: false, message: 'OTP Expired'});
        }

        user.isAccountVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpiredAt= 0;

        await user.save();
        return res.json({sucess: true, message: 'Email verified successfully'})
        
    } catch (error) {
       return  res.json({sucess: false, message: error.message});
    }
}
//check if user is authenticated
export const isAuthenticated = async(req, res)=>{
    try {
        return res.json({success: true });
    } catch (error) {
          res.json({sucess: false, message: error.message});
        
    }
}

// Send Password Resest otp
export const sendResetOtp = async(req,res)=>{
    const {email} = req.body;

    if(!email){
        return res.json({sucess: false, message:  'Email is required'})
    }
    try {

        const user = await userModel.findOne({email});
        if(!user){
            return res.json({sucess: false,  message: 'User not found'})
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000))
 
         user.resetOtp = otp;
         user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000

         await user.save();

         const mailOption = {
            from: process.env.SENDER_EMAIL, 
            to: user.email,
            subject: 'Password Reset Otp',
          //  text: `Your OTP for resetting your pssword is ${otp}. Use this OTP to proceed with resetting your password.`,
            html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", 
                user.email)
         };

         await transporter.sendMail(mailOption);

         return res.json({success: true, message: 'OTP sent to your email'});

        
    } catch (error) {
        return res.json({sucess: false, message:  error.message})
    }
}

//Reset User Password
export const resetPassword = async(req, res)=>{
    const {email, otp, newPassword} = req.body;

    if(!email || !otp || !newPassword){

    return res.json({success: false, message: 'Email, OTP and new password are required'});

    }

    try {
        
        const user = await userModel.findOne({email});
        if(!user){
            return res.json({success: false, message: 'User Not Found'});
        }

        if(user.resetOtp === "" || user.resetOtp !== otp){
            return res.json({success: false, message: 'Invalid OTP'});
        }

        if(user.resetOtpExpireAt < Date.now()){
            return res.json({success: false, message: 'OTP is Expired'})
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;

        await user.save();

        res.json({success: true, message: 'Password has been reset successfully'});
        

    } catch (error) {
    return res.json({success: false, message: error.message});
    }

}
