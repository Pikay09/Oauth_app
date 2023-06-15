const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth").OAuth2Strategy;

const GitHubStrategy = require("passport-github").Strategy;

// Load environment variables from .env file
require("dotenv").config();

// Create an Express application
const app = express();

// Set the template engine to EJS
app.set("view engine", "ejs");

//Use express session middleware to manage session
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false, //Do not resave data if no changes are made to our session ID(SID)
    saveUninitialized: false, //Do not save uninitialized sessions to storage
  })
);

//Initialize passport
app.use(passport.initialize());

//Initialize passport session
app.use(passport.session());

// Get the port number from the environment variables
const port = process.env.PORT || 3000;

// Use the Express URL parser
app.use(express.urlencoded({ extended: false }));

// Serve static files such as CSS and images with the response
app.use(express.static("public"));

//Implement Google OAuth strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    function (accessToken, refreshToken, profile, cb) {
      return cb(null, profile);
    }
  )
);

//Implement GitHub OAuth Strategy
passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: process.env.GITHUB_CALLBACK_URL,
    },
    function (accessToken, refreshToken, profile, cb) {
      return cb(null, profile);
    }
  )
);

//Serialize and deserialize the user data
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

//Load index page on web page load
app.get("/", (req, res) => {
  if (req.user) {
    res.redirect("/protected");
  } else {
    res.render("index.ejs");
  }
});

//Implement Google Authentication Route
app.get(
  "/auth/google",
  passport.authenticate("google", {
    //Specify the permission that user is being asked to grant access to
    scope: ["profile", "email"],
    prompt: "select_account",
  })
);

//Implement Git Hub Authentication Route
app.get(
  "/auth/github",
  passport.authenticate("github", {
    scope: ["read:user", "user:email"],
    login:false
  })
);

//Define callback route
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    res.redirect("/protected");
  }
);

//Define callback route
app.get(
  "/auth/github/callback",
  passport.authenticate("github", { failureRedirect: "/" }),
  (req, res) => {
    res.redirect("/protected");
  }
);

//Define protected route
app.get("/protected", (req, res) => {
  if (req.user) {
    console.log(req.user);
    res.render("welcome.ejs", { user: req.user });
  } else {
    res.redirect("/");
  }
});

//Define Logout Route
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      res.sendStatus(500);
    } else {
      req.logout(() => {
        console.log("Logged User Out");
      });
      res.redirect("/");
    }
  });
});

// Start the server and listen for incoming requests on the specified port
app.listen(port, () => {
  // Log a message indicating that the server is running
  console.log(`OAuth app listening on port ${port}`);
});
