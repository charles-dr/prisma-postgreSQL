import type { Express } from "express";
import passport from "passport";
import passportLocal from "passport-local";
import passportJWT from "passport-jwt";
import prisma from "./prisma";
import { appConfig } from "./app";
import { comparePassword } from "../utils/password";

const LocalStrategy = passportLocal.Strategy;
const JWTStrategy = passportJWT.Strategy;
const ExtractJWT = passportJWT.ExtractJwt;

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
};
