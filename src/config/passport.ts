import type { Express } from "express";
import passport from "passport";
import passportLocal from "passport-local";
import passportJWT from "passport-jwt";
import Auth0Strategy from "passport-auth0";
import prisma from "./prisma";
import { appConfig } from "./app";
import { comparePassword } from "../utils/password";

const LocalStrategy = passportLocal.Strategy;
const JWTStrategy = passportJWT.Strategy;
const ExtractJWT = passportJWT.ExtractJwt;

var auth0Strategy = new Auth0Strategy(
  {
    domain: `${process.env.AUTH0_ISSUER_URL}`,
    clientID: `${process.env.AUTH0_CLIENT_ID}`,
    clientSecret: `${process.env.AUTH0_SECRET}`,
    callbackURL: `${process.env.AUTH0_BASE_URL}`,
    passReqToCallback: true,
  },
  function (req, accessToken, refreshToken, extraParams, profile, done) {
    //
    // State value is in req.query.state ...
    //
    return done(null, profile);
  }
);

export const configure = (app: Express) => {
  app.use(passport.initialize());
  app.use(passport.session());

  passport.use(
    "login",
    new LocalStrategy(
      { usernameField: "email", passwordField: "password" },
      (email, password, done) => {
        return prisma.user
          .findUnique({ where: { email } })
          .then(async (user) => {
            if (!user)
              return done(undefined, false, {
                message: `Email ${email} not found.`,
              });

            const isMatch = await comparePassword(password, user.password);
            if (isMatch) return done(undefined, user);
            return done(undefined, false, {
              message: "Invalid email or password",
            });
          })
          .catch((err) => done(err));
      }
    )
  );

  passport.use(
    new JWTStrategy(
      {
        jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
        secretOrKey: appConfig.JWT_SECRET,
      },
      (jwtPayload, cb) => {
        return prisma.user
          .findUnique({ where: { id: jwtPayload.id } })
          .then((user) => {
            if (!user) throw new Error("Not found the user");
            return cb(null, user);
          })
          .catch((err) => {
            return cb(err);
          });
      }
    )
  );

  passport.use(auth0Strategy);
};
