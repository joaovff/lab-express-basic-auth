const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const User = require("../models/User.model");
const { isLoggedIn, isLoggedOut } = require("../middleware/route-guard");

const saltRounds = 10;

router.get("/signup", (req, res, next) => {
  try {
    res.render("auth/signup");
  } catch (error) {
    next(error);
  }
});

router.post("/signup", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.render("auth/signup", {
        errorMessage: "All fields are required!",
      });
    }
    const passwordRegex =
      /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/gm;
    if (!passwordRegex.test(password)) {
      return res.status(500).render("auth/signup", {
        errorMessage: `Password needs to be at least 6 characters
            and must contain one uppercase letter, one lowercase letter,
            a number and a special character.`,
      });
    }
    const salt = await bcrypt.genSalt(saltRounds);
    const passwordHash = bcrypt.hashSync(password, salt);
    await User.create({ username, passwordHash });
    res.redirect("/login");
  } catch (error) {
    if (error instanceof mongoose.Error.ValidationError) {
      res.status(500).render("auth/signup", { errorMessage: error.message });
    } else if (error.code === 11000) {
      res.status(500).render("auth/signup", {
        errorMessage: "Username already in use",
      });
    } else {
      next(error);
    }
  }
});

router.get("/login", (req, res, next) => {
  try {
    res.render("auth/login");
  } catch (error) {
    next(error);
  }
});

router.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const { currentUser } = req.session;

    if (username === "" || password === "") {
      return res.render("auth/login", {
        errorMessage: "Please enter both useranme and password",
      });
    }
    const user = await User.findOne({ username });
    if (!user) {
      return res.render("auth/login", {
        errorMessage:
          "Username is not registered. Please try another username.",
      });
      //checking if the password matches
    } else if (bcrypt.compareSync(password, user.passwordHash)) {
      req.session.currentUser = user;
      res.redirect("/");
    } else {
      res.render("auth/login", { errorMessage: "Incorrect password." });
    }
  } catch (error) {
    next(error);
  }
});

module.exports = router;
