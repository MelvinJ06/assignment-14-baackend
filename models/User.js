const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required : true
    },

    email:{
        type: String,
        required : true,
        unique : true
    },

    password:{
        type: String,
        required : true,
    },
    resetPasswordToken: {
        type: String,
    },
    resetPasswordExpires: {
        type: Date,
    }
});

const user = mongoose.model("User", userSchema);

module.exports = user;