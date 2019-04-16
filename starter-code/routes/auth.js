const express = require('express');
const bcrypt = require('bcrypt');
const User = require('../models/user');
const router = express.Router();
const zxcvbn = require('zxcvbn');


router.get('/register', (req, res, next) => {
  res.render('auth/register');
});

router.get('/login', (req, res, next) => {
  res.render('auth/login');
});

router.get('/logout', (req, res, next) => {
  req.session.destroy(() => {
    res.redirect("/")
  })
});

router.post("/register", (req, res, next) => {
  const { username, password } = req.body;
  const salt = bcrypt.genSaltSync();
  const hashPassword = bcrypt.hashSync(password, salt);

  if (username === "" || password === "") {
    res.render("auth/register", {
      errorMessage: "You need to fill in both fields"
    })
    return;
  }
  //check password strength
  User.findOne({ username })
    .then(user => {
      if (user) {
        res.render("auth/register", {
          errorMessage: "There is already a user with this username, plz choose another one"
        })
        return;
      }
      User.create({ username, password: hashPassword })
        .then(() => {
          res.render("auth/secret")
        })
        .catch(err => {
          console.error("Error when registering new user", err)
        })
    })
    .catch(err => {
      console.error("Error while lookinf for user", err)

    })
});

router.get('/secret', (req, res, next) => {
  if (req.session.loggedInUser) {
    res.render('auth/secret');
  } else {
    res.render("error")
  }
});

router.get('/main', (req, res, next) => {
  if (req.session.loggedInUser) {
    console.log(req.session.loggedInUser)
    res.render('auth/main');
  } else {
    res.render("auth/login")
  }
});

router.post("/login", (req, res, next) => {
  const {username, password} = req.body;
  if (username === "" || password === "") {
    res.render("auth/login", {
      errorMessage: "You need to fill in both fields"
    })
    return;
  }

  User.findOne({username})
  .then( user => {
    console.log(user)
    if (!user) {
      res.render("auth/login", {
        errorMessage: "Username not found"
      })
    }
    if (bcrypt.compareSync(password, user.password)) {
      req.session.loggedInUser = true;
      res.redirect("/secret");
    } else {
      res.render("auth/login", {
        errorMessage: "wrong password"
      })
    }
  })
  .catch(err => {
    console.error("error while finding user", err)
  })
})

module.exports = router;