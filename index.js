import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import { render } from "ejs";

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: "TOPSECRET",
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24,  
  }
}));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "admin",
  port: 5432,
});

db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secret", (req,res) => {
  if (req.isAuthenticated) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});

app.post("/register", async (req, res) => {
  let email = req.body.username;
  let password = req.body.password;

  try{
    const checkRes = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    
    if (checkRes.rows.length > 0){
      res.send("Email already exists. Try logging in.");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.log("Error hashing password:", err);
        } else {
          const result = await db.query("INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *", [email, hash]);
          const user = result.rows[0];
          req.login(user, (err) => {
            res.redirect("/secrets")
          })
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", passport.authenticate("local", {
  successRedirect: "/secret",
  failureRedirect: "/login"
}));

passport.use(new Strategy(async function verify(username, passport, cb) {
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storesHashPassword = user.password;
      bcrypt.compare(passport, storesHashPassword, (err, result) => {
        if (result) {
          return cb(null, user);
        } else {
          return cb(null, false);
        }
      });
    } else {
      return cb("User not found")
    }
  } catch (error) {
    return cb(err)
  }
}));

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
