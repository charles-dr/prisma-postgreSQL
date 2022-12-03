import { Router } from "express";
import passport from "passport";
import prisma from "../config/prisma";
// import * as passport from "../config/passport";

const router = Router();

router.use((req, res, next) => {
  console.log("passport.middleware.before");
  next();
});

router.use(passport.authenticate("jwt", { session: false }));

router.post("/s", (req, res) => {
  console.log("did you call me?");
  return res
    .status(200)
    .json({ status: true, message: "you called [POST]posts/." });
});

export default router;
