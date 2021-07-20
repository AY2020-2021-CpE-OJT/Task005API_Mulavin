//index.js
const Joi = require ('joi');
const express = require ('express');
const MongoClient = require('mongodb').MongoClient;
const ObjectId = require('mongodb').ObjectID;
const { error } = require('joi/lib/types/lazy');
const number = require('joi/lib/types/number');

const passport = require('passport');
const localStrategy = require('passport-local').Strategy;
const jwtStrategy = require('passport-jwt').Strategy;
const jwtExtract = require('passport-jwt').ExtractJwt;
const jwt = require('jsonwebtoken');
const BCrypt = require('bcryptjs');
const routerSecured = express.Router();

const app = express();

app.use(express.json());

app.use('/user', passport.authenticate('jwt', { session: false }), routerSecured);

MongoClient.connect('mongodb+srv://usernum1:usernum1pass@contactnumbers.zc2ev.mongodb.net/myFirstDatabase?retryWrites=true&w=majority',{
    useUnifiedTopology: true
}).then(client => {
    console.log('Connected to Database');
    const db = client.db('forContactsDatabase');
    const numberCollection = db.collection('contactsCollection');
    const usersCollection = db.collection('usersCollection');

    passport.use(new jwtStrategy({
        secretOrKey: 'SUPER_SECRET_CODE',
        jwtFromRequest: jwtExtract.fromAuthHeaderAsBearerToken()
    }, async (token, done) => {
        try {
            return done(null, token.user);
        } catch (error) {
            return done (error);
        }
    }));
    passport.use(
        'signup', new localStrategy({
            usernameField: 'email',
            passwordField: 'password'
        }, async(email, password, done) =>{
            try{
                BCrypt.hash(password, 10, (err, hash) =>{
                    usersCollection.findOne({email}, (err, result) => {
                        if(result) return done(null,{message: 'The e-mail exists'});
                        const password = hash;
                        usersCollection.insertOne({email, password});
                        usersCollection.findOne({email, password}, (err, result) => {
                            return done(null, result);
                        });
                    });
                });
            } catch (error){
               return done(error);
            }
        })
    );
    passport.use(
        'login', new localStrategy({
            usernameField: 'email',
            passwordField: 'password'
        }, async(email, password, done) =>{
            try {
                usersCollection.findOne({email}, (err, user) =>{
                    if(err) throw err;
                    if(!user){
                        return done(null, false, {message: 'User Not Found'});
                    }
                    usersCollection.findOne({email}, (err, userresult) =>{
                        if(err) throw err;
                        BCrypt.compare(password, userresult.password, (err, result) => {
                            if(!result){
                                return done(null, false, {message: 'Invalid Password'});
                            }return done(null, result, {message: 'Successful Log-in'});
                        });  
                    });
                });
            } catch (error) {
                return done(error);
            }
        })
    );
    const port = process.env.PORT || 3000;
    app.listen(port, () => console.log(`Listening from port ${port}...`));

    console.log ('This is a practice API. Hi!!!');

    app.post('/signup', passport.authenticate('signup',{session: false}),
    async(req, res, next)=>{
        res.json(req.user);
    });
    app.post('/login', async(req, res, next)=>{
        passport.authenticate('login', async(err, user, info) =>{
            try {
                if(!user){
                    res.send(info)
                }
                req.login(user,{session: false}, async(error)=>{
                    if (error) return next(error);
                    const token = jwt.sign({user: {_id: user._id, email: user.email}}, 'SUPER_SECRET_CODE');
                    return res.json({token})
                })
            } catch (error) {
                return next(error);
            }
        })(req, res, next)
    });
    routerSecured.get('/userAccount', (req, res, next)=>{
        res.json({
            message: 'You have succesfully entered the secret route',
            user: req.user,
            token: req.query.secret_token
        })
    })
    app.get('/', (req, res) => {
        res.send('Hi!!!! This is my sample API');
    })
    routerSecured.get('/contactNumbers', (req, res) => {
        db.collection('contactsCollection').find({}).toArray((err, result) => {
            if (err) throw err;
                res.send(result);
            });
    });
    app.get('/contactNumbers/totalCount', (req, res) => {
        db.collection('contactsCollection').countDocuments({}, (err, result) => {
            if (err) res.send(result);
            else res.json(result);
            });
    });
    routerSecured.get('/:id', (req, res) => {
        numberCollection.find({_id: new ObjectId(req.params['id'])}).toArray((err, result) => {
            if (err) throw err;
            res.send(result[0]);
        });
    });
    routerSecured.get('/contactNumbers/:id', (req, res) => {
        numberCollection.find({_id: new ObjectId(req.params['id'])}).toArray((err, result) => {
            if (err) throw err;
            res.send(result[0]);
        });
    });
    routerSecured.post('/contactNumbers', (req, res) =>{
        const { error } = validateContacts(req.body);
        if (error){
            res.send(error.details[0].message);
            return;
        }
        numberCollection.insertOne(req.body);
        res.send(req.body);
    });
    routerSecured.put('/contactNumbers/:_id', (req, res) => {
        numberCollection.updateOne({_id: new ObjectId(req.params['_id'])}, 
        {$set: {
            last_name: req.body.last_name,
            first_name: req.body.first_name,
            phone_numbers: req.body.phone_numbers
        }}, (err, result) => {
            if (err) throw err;
            res.send(result);
        });
    });
    routerSecured.delete('/contactNumbers/:_id', (req, res) => {
        numberCollection.deleteOne({_id: new ObjectId(req.params['_id'])}, (err, result) => {
            if (err) throw err;
            res.send(result);
        });
    });
function validateContacts(contact){
    const schema = {
        last_name : Joi.string().min(3).required(),
        first_name : Joi.string().min(3).required(),
        phone_numbers : Joi.array().min(2).required(),
    };
    return Joi.validate(contact, schema);
}
});