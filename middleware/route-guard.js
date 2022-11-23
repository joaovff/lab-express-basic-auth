const isLoggedIn = (req, res, next) => {
  if (!req.session.currentUser) {
    // se não estiver logado, manda p pagina de login
    return res.redirect("/login");
  }
  next();
};

const isLoggedOut = (req, res, next) => {
  if (req.session.currentUser) {
    return res.redirect("/");
  }
  next();
};

module.exports = { isLoggedIn, isLoggedOut };
