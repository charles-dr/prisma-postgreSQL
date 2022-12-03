import { Router } from "express";
import prisma from "../config/prisma";
import * as passport from "../config/passport";

const router = Router();

router.route("/").post(passport.isAuthenticated, async (req, res) => {
  return res.status(200).send("you called [POST]posts/.");
});

export default router;
