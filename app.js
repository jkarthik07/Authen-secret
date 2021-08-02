require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate= require('mongoose-findorcreate');
//refer to authenticate google sigin "https://www.passportjs.org/packages/passport-google-oauth20/"

const app = express();

//Order of the code doesn't change while using passport,sessions..!!

app.use(express.static("public"))
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended :true}))

app.use(session({
    secret: "Our massive secret",
    resave: false,
    saveUninitialized: false 
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get('/',(req,res)=>{
    res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ["profile"] })
);

  app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secret.
    res.redirect('/secrets');
  });

app.get('/login',(req,res)=>{
    res.render("login");
});


app.get('/register',(req,res)=>{
    res.render("register");
});

app.get("/secrets",(req,res)=>{
    if(req.isAuthenticated()){
        User.find({"secret":{$ne:null}},(err,foundUser)=>{
            if(err){
                console.log(err);
            } else{
                if(foundUser){
                    res.render("secrets",{userSecret: foundUser});
                }
            }
        });
    } else{
        res.redirect('/login');
    }
});

app.get("/logout",(req,res)=>{
    req.logout();
    res.redirect('/');
})

app.get("/submit",(req,res)=>{
    if(req.isAuthenticated()){
        res.render("submit");
    } else{
        res.redirect('/login');
    }
});

app.post("/submit",(req,res)=>{
    const userSecret = req.body.secret;

    User.findById(req.user.id,(err,found)=>{
        if(err){
            console.log(err);
        } else{
            if(found){
                found.secret= userSecret;
                found.save(()=>{
                    res.redirect("/secrets");
                })
            }
        }
    })
})

app.post('/register',(req,res)=>{
    User.register({username: req.body.username},req.body.password, (err,user)=>{
        if(err){
            console.log(err);
            res.redirect('/register');
        } else{
            passport.authenticate("local")(req,res,()=>{
                res.redirect('/secrets');
            });
        }
    });
});

app.post('/login',(req,res)=>{
    
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err)=>{
        if(err){
            console.log(err);
        } else{
            passport.authenticate("local")(req,res, ()=>{
                res.redirect('/secrets');
            });
        }
    });
    
});

app.listen(process.env.PORT || 3000,()=>{
    console.log("SERVER IS RUNNING ON PORT 3000")
})

//Authenticate using bcrypy,salt & hash 

// app.post('/login',(req,res)=>{
    
//     const username = req.body.username;
//     const password = req.body.password;

//     User.findOne({email: username},(err,found)=>{
//         if(err){
//             console.log(err);
//         } else{
//             if(found){
//                 bcrypt.compare(password, found.password, (err,result)=>{
//                     if(result===true){
//                         res.render("secrets");
//                     }
//                 })
//             }
//         }
//     });
// });

// app.post('/register',(req,res)=>{
//     bcrypt.hash(req.body.password, saltRounds, (err,hash)=>{
//         const newUser = new User({
//             email: req.body.username,
//             password: hash
//         });
//         newUser.save((err)=>{
//             if(err){
//                 console.log(err)
//             } else{
//                 res.render("secrets");
//             }
//         });
//     });
// });