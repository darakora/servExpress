const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const keys = require('../config/keys');
const errorHandler = require('../utils/errorHandler');

module.exports.login = async function(req, res) {
    const candidate = await User.findOne({email: req.body.email});

    if(candidate){
        //Check password, user exist
        const passwordResult = bcrypt.compareSync(req.body.password, candidate.password);
        if(passwordResult){
            //Generate token

            const token = jwt.sign({
                email: candidate.email,
                userId: candidate._id
            }, keys.jwt, {expiresIn: 60 * 60});

            res.status(200).json({
                token: `Bearer ${token}`
            })
        }else {
            //Password not configure. Try again'
            res.status(401).json({
                message: 'Password not configure. Try again'
            })
        }
    }else {
        //no user, error
        res.status(404).json({
            message: 'User with this email not exist'
        })
    }
};

module.exports.register = async function(req, res){
    //email password
    const candidate = await User.findOne({email: req.body.email});

    if (candidate){
        //User exist, must have error
        res.status(409).json({
            message: 'This email exist, try another'
        })
    }else {
        //Must to create user
        const salt = bcrypt.genSaltSync(10);
        const password = req.body.password;
        const user = new User({
            email: req.body.email,
            password: bcrypt.hashSync(password, salt)
        });

        try {
            await user.save();
            res.status(201).json(user)
        }catch (e) {
            //error
            errorHandler(res, e)
        }
    }
};

