require("dotenv").config();
const bodyParser = require("body-parser");
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));

// musi być we właściwej kolejności - przed connectem
app.use(session({
  secret: "Our little secret czy coś..",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");
// mongoose.set("useCreateIndex", true);

// must be a mongoose Schema to be able to accept plugins
const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

// use to hash, salt passwords, save user data in DB
userSchema.plugin(passportLocalMongoose);

// // this encryption plugin must be placed before the mongoose model it refers to
// userSchema.plugin(encrypt, {
//   // this uses the .env module to hide sensitive keys
//   secret: process.env.SECRET,
//   encryptedFields: ["password"]
// });

const User = new mongoose.model("User", userSchema);

// local login strategy, serialize and deserialize
passport.use(User.createStrategy());

// used to serialize the user for the session with local-mongoose
passport.serializeUser(User.serializeUser());

// used to deserialize the user with local-mongoose
passport.deserializeUser(User.deserializeUser());

//TODO
app.get("/", function(req, res) {
  res.render("home");
});

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/secrets", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});

app.post("/register", function(req, res) {

  User.register({
    username: req.body.username
  }, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", function(req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.listen(4000, function() {
  console.log("Server started on port 4000");
});