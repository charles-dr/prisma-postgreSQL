import passport from "passport";
import passportLocal from "passport-local";
import { Request, Response, NextFunction } from "express";
import prisma from "./prisma";
import { comparePassword } from "../utils/password";
console.log("[Passport][Config]");

const LocalStrategy = passportLocal.Strategy;

passport.serializeUser<any, any>((req, user, done) => {
  console.log("[passport.serializeUser]", user);
  done(undefined, user);
});

passport.deserializeUser((id, done) => {
  console.log("[passport.deserializeUser]", id);
  // User.findById(id, (err: NativeError, user: UserDocument) => done(err, user));
  return prisma.user
    .findUnique({ where: { id: id as number } })
    .then((user) => {
      if (user) {
        return done(undefined, user);
      }
      return done(new Error("Not found the user!"), false);
    })
    .catch((err) => {
      return done(err, false);
    });
});

passport.use(
  new LocalStrategy(
    { usernameField: "email", passwordField: "password" },
    (email, password, done) => {
      console.log("passport.local", email, password);
      return prisma.user
        .findUnique({ where: { email } })
        .then(async (user) => {
          if (!user)
            return done(undefined, false, {
              message: `Email ${email} not found.`,
            });

          // compare password.
          const isMatch = await comparePassword(password, user.password); // TODO: some func to compare password.
          if (isMatch) return done(undefined, user);
          return done(undefined, false, {
            message: "Invalid email or password",
          });
        })
        .catch((err) => done(err));
    }
  )
);

export const isAuthenticated = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (req.isAuthenticated()) {
    next();
  } else {
    throw new Error("Authenticaion failed");
  }
};
