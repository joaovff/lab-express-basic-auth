const router = require("express").Router();
const { isLoggedIn, isLoggedOut } = require("../middleware/route-guard");

router.get("/", (req, res, next) => {
  res.render("index");
});

router.get("/main", (req, res, next) => {
  res.render("main");
});

router.get("/private", isLoggedIn, (req, res, next) => {
  res.render("private");
});

module.exports = router;
