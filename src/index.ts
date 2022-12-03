import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import flash from "express-flash";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import type { VerifyFunctionWithRequest } from "passport-local";
import * as routers from "./routes";
import * as passportConfig from "./config/passport";

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cors());
app.use(
  session({
    secret: "keyboard-cat",
    resave: true,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// passport.use(new LocalStrategy({ usernameField: "email" }), authenticateUser);
// passport.use(
//   new LocalStrategy(
//     {
//       usernameField: "email",
//       passwordField: "password",
//     },
//     (email, password, done) => {
//       console.log("you reached me", email);
//       const user = null;
//       if (!user) {
//         return done(undefined, false, { message: `Email ${email} not found.` });
//       }
//       // compare password.
//       const passwordMatched = true;
//       const matchCheckException = new Error(
//         "Unexpected error while checking password match"
//       );

//       if (matchCheckException) {
//         return done(matchCheckException);
//       }
//       if (passwordMatched) {
//         return done(undefined, user);
//       } else {
//         return done(undefined, false, { message: "Invalid email or password" });
//       }
//     }
//   )
// );
// passport.serializeUser((user, done) => {
//   done(undefined, user);
// });
// passport.deserializeUser((id, done) => {
//   // User.findById(id, (err: NativeError, user: UserDocument) => done(err, user));
// });

app.use((req, res, next) => {
  res.locals.user = req.user;
  next();
});

app.use((req, res, next) => {
  console.log("app.middleware.user", req.user);
  //   // After successful login, redirect back to the intended page
  //   if (!req.user &&
  //   req.path !== "/login" &&
  //   req.path !== "/signup" &&
  //   !req.path.match(/^\/auth/) &&
  //   !req.path.match(/\./)) {
  //       req.session.returnTo = req.path;
  //   } else if (req.user &&
  //   req.path == "/account") {
  //       req.session.returnTo = req.path;
  //   }
  next();
});

app.use("/test", (req, res, next) => {
  console.log("Request URL:", req.originalUrl, req.path);
  next();
});

app.use("/users", routers.user);
app.use("/posts", routers.post);
app.use("/auth", routers.auth);

app.use((req, res, next) => {
  console.log("app.middleware.after");
  return res.status(404).send("Not found or invalid params");
});

app.listen(3000, () => {
  console.log("🚀 Server ready at: http://localhost:3000");
});
