import { Router } from "express";
import bcrypt from "bcrypt";
import passport from "passport";
import jwt from "jsonwebtoken";
import prisma from "../config/prisma";
import { appConfig } from "../config/app";
import { comparePassword, encryptPassword } from "../utils/password";

const router = Router();

router.use((req, res, next) => {
  console.log("auth.router.middleware");
  next();
});

router.post("/register", async (req, res) => {
  const { email, name, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      status: false,
      message: "email/password are required",
    });
  }

  return Promise.resolve()
    .then(async () => {
      const hashedPassword = await encryptPassword(password);

      const emailUsed = await prisma.user.findUnique({ where: { email } });
      if (emailUsed) {
        throw new Error("User already exists with email");
      }
      console.log("register.email.available", email);

      const user = await prisma.user.create({
        data: { email, name, password: hashedPassword },
      });
      console.log("user.created?", user);
      return {};
    })
    .then((user) => {
      // console.log("[POST]/register.user.created", user);
      return res.json(user);
    })
    .catch((err) => {
      return res.status(400).send({
        status: false,
        message: err.message,
      });
    });
});

router.post("/login", async (req, res, next) => {
  const { email, password } = req.body;

  return new Promise((resolve, reject) => {
    if (!email || !password) {
      reject(new Error("email, password are required."));
    }
    passport.authenticate("local", { session: false }, (err, user, info) => {
      if (err) reject(err);
      if (info?.message) reject(new Error(info.message));

      req.login(user, { session: false }, (err) => {
        if (err) {
          reject(err);
        }
        // generate a signed son web token with the contents of user object and return it in the response
        // const token = jwt.sign(user, "your_jwt_secret");
        // return res.json({ user, token });
        resolve(user);
      });

      // console.log(req.login);
      // resolve(user);
    })(req, res, next);
  })
    .then((user) => {
      console.log("login.response", user);
      const token = jwt.sign(user!, appConfig.JWT_SECRET, {
        expiresIn: "7d",
      });
      return res.status(200).json({ user, token });
    })
    .catch((err) => {
      return res.status(400).json({
        status: false,
        message: err.message,
      });
    });
});

export default router;
