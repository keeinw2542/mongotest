var mongodb = require('mongodb');
var ObjectID = mongodb.ObjectID;
var crypto = require('crypto');
var express = require('express')
var bodyParser = require('body-parser')

require("dotenv").config()
//CREAT FUNTION TO RANDOM SALT
var genRandomString = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
        .toString('hex') //convert to hex format
        .slice(0,length);
    };

var sha512 = function(password,salt){
    var hash =crypto.createHmac('sha512',salt);
    hash.update(password);
    var value = hash.digest('hex');
    return {
        salt:salt,
        passwordHash:value
    };
};

function saltHashPassword(userPassword) {
    var salt = genRandomString(16);
    var passwordData =sha512(userPassword,salt);
    return passwordData;
}

function checkHashPassword(userPassword,salt) {
    var passwordData = sha512(userPassword,salt);
    return passwordData;
}

//Create Express Service
var app =express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

//Create Express Service
var MongoClient = mongodb.MongoClient;

//Connection URL
var url =process.env.MONGO_URL
//var url = 'mongodb://localhost:27017' //27017 is default or port

MongoClient.connect(url,{useNewUrlParser: true},function(err,client){
    if (err) {
        console.log('Unable to connect to the mongoDB server. ERROR',err);
    } else {
        //Register
        app.post('/register',(request,response,next)=>{
            var post_data = request.body;

            var plaint_password = post_data.password;
            var hash_data = saltHashPassword(plaint_password);

            var password =hash_data.passwordHash; //Save password hash
            var salt =hash_data.salt; //save salt

            var name =post_data.name;
            var email =post_data.email;

            var insertJson= {
                'email':email,
                'password':password,
                'salt':salt,
                'name':name
            };
            var db = client.db('keetest');

            //Check exist email
            db.collection('user')
                .find({'email':email}).count(function(err,number){
                    if(number != 0){
                        response.json('email alrady exists');
                        console.log('email alrady exists');
                    }
                    else{
                        //Insert data 
                        db.collection('user')
                            .insertOne(insertJson,function(err,res){
                                response.json('Registration success');
                                console.log('Registration suscess');
                            })
                    }
                })

        })

        app.post('/login',(request,response,next)=>{
            var post_data = request.body;

            var email =post_data.email;
            var userPassword =post_data.password;
            
            var db = client.db('keetest');

            //Check exist email
            db.collection('user')
                .find({'email':email}).count(function(err,number){
                    if(number == 0){
                        response.json('email not exists');
                        console.log('email not exists');
                    }
                    else{
                        //Insert data 
                        db.collection('user')
                            .findOne({'email':email},function(err,user){
                                var salt =user.salt; //get salt from user
                                var hashed_password = checkHashPassword(userPassword,salt).passwordHash;//hash password with salt
                                var encrypted_password = user.password;//getpassword from user
                                if (hashed_password ==encrypted_password){
                                    response.json('Login success');
                                    console.log('Login suscess');
                                }
                                else {
                                    response.json('worng password');
                                    console.log('worng password');
                                }
                            })
                    }
                })

        })

        //Start Web Server
        app.listen(3000,()=>{
            console.log('Connected to mongoDB Server ,Webservice runing on port 3000');
        })
    }
});