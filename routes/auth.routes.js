const { Router } = require("express");
const router = new Router();
const bcryptjs = require("bcryptjs");
const saltRounds = 10;
const User = require("../models/User.model");

router.get("/signup", (req, res) => res.render("auth/signup"));

router.post("/signup", (req, res, next) => {
    const { username, password } = req.body;
   
    if (!username || !password) {
      res.render("auth/signup", {
        errorMessage:
          "All fields are mandatory. Please provide your username, username and password.",
      });
      return;
    }
  
    const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
    if (!regex.test(password)) {
      res.status(500).render("auth/signup", {
        errorMessage:
          "Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.",
      });
      return;
    }
  
    bcryptjs
      .genSalt(saltRounds)
      .then((salt) => bcryptjs.hash(password, salt))
      .then((hashedPassword) => {
        console.log(`Password hash: ${hashedPassword}`);
        return User.create({ username, password: hashedPassword });
      })
      .then((dataDB) => {
        //console.log("Newly created user is: ", dataDB);
        //res.status(201).send('User created successfully');
        res.redirect("/userProfile");
      })
      .catch((error) => {
        if (error instanceof mongoose.Error.ValidationError) {
          res.status(500).render("auth/signup", { errorMessage: error.message });
        } else if (error.code === 11000) {
          console.log(
            " Username and username need to be unique. Either username or username is already used. "
          );
  
          res.status(500).render("auth/signup", {
            errorMessage: "User not found and/or incorrect password.",
          });
        } else {
          next(error);
        }
      }); 
  });

  router.get("/login", (req, res) => res.render("auth/login"));

router.post("/login", (req, res, next) => {
    console.log('SESSION =====> ', req.session);
  const { username, password } = req.body;

  if (username === "" || password === "") {
    res.render("auth/login", {
      errorMessage: "Please enter both, username and password to login.",
    });
    return;
  }

  User.findOne({ username })
    .then((user) => {
      if (!user) {
        console.log("User not registered. ");
        res.render("auth/login", {
          errorMessage: "User not found and/or incorrect password.",
        });
        return;
      } else if (bcryptjs.compareSync(password, user.password)) {
        req.session.currentUser = user;
        res.redirect('/userProfile');
        
        //res.render("user/user-profile", { user });
      } else {
        console.log("Incorrect password. ");
        res.render("auth/login", {
          errorMessage: "User not found and/or incorrect password.",
        });
      }
    })
    .catch((error) => next(error));
});
router.post('/logout', (req, res, next) => {
    req.session.destroy(err => {
      if (err) next(err);
      res.redirect('/');
    });
  });

  router.get("/userProfile", (req, res) => res.render("user/user-profile", { userInSession: req.session.currentUser }));

module.exports = router;
