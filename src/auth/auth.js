import express, { text } from 'express'
import passport from 'passport'
import LocalStrategy from 'passport-local'
import crypto from 'crypto'
import { Mongo } from '../database/mongo.js'
import jwt from 'jsonwebtoken'
import { ObjectId } from 'mongodb'

const collectionName = 'users'

passport.use(new LocalStrategy({usernameField: 'email'}, async(email,password, callback) => {
    const user = await Mongo.db
    .collection(collectionName)
    .findOne({email: email})

    if (!user){
        return callback(null, false)
    }

    const saltBuffer = user.salt.saltBuffer

    crypto.pbkdf2(passport, saltBuffer, 310000, 16, 'sha256', (err, hashedPassword) => {
        if(err){
            return callback(null, false)
        }

        const userPasswordBuffer = saltBuffer.from(user.password.buffer)


        if(!crypto.timingSafeEqual(userPasswordBuffer, hashedPassword)){
            return callback(null, false)
        }

        const {password, salt, ...rest} = user 

        return callback (null, rest)
    })



}))

// rota

const  authRouter = express.Router()

authRouter.post('/signup', async (req, res) => { // Corrigido de '/sigunp' para '/signup'
    const checkUser = await Mongo.db
        .collection(collectionName)
        .findOne({ email: req.body.email });

    if (checkUser) {
        return res.status(500).send({
            success: false,
            statusCode: 500,
            body: {
                text: 'User already exists',
            },
        });
    }

    const salt = crypto.randomBytes(16); // Corrigido 'randomBYtes' para 'randomBytes'
    crypto.pbkdf2(req.body.password, salt, 310000, 16, 'sha256', async (err, hashedPassword) => { // Corrigido 'passport' para 'password'
        if (err) {
            return res.status(500).send({
                success: false,
                statusCode: 500,
                body: {
                    text: 'Error on crypto password',
                    err: err,
                },
            });
        }

        const result = await Mongo.db
            .collection(collectionName)
            .insertOne({
                email: req.body.email,
                password: hashedPassword, // Corrigido 'passport' para 'password'
                salt,
            });

        if (result.insertedId) {
            const user = await Mongo.db
                .collection(collectionName)
                .findOne({ _id: new ObjectId(result.insertedId) });

            const token = jwt.sign(user, 'secret');

            return res.send({
                success: true,
                statusCode: 200,
                body: {
                    text: 'User registered correctly!',
                    user,
                    logged: true,
                },
            });
        }
    });
});



//rota

export default authRouter