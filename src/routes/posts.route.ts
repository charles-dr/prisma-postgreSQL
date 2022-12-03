import { Router } from "express";
import passport from "passport";
import type { User } from ".prisma/client";
import prisma from "../config/prisma";

const router = Router();

router.use(passport.authenticate("jwt", { session: false }));

router.post("/", (req, res) => {
  const { title, content } = req.body;
  const published = !!req.body.published;
  const authorId = (req.user as User).id;

  return Promise.resolve()
    .then(async () => {
      if (!title) throw new Error("Title is required!");

      const post = await prisma.post.create({
        data: {
          title,
          content,
          authorId,
          published,
        },
      });

      return res.status(200).json(post);
    })
    .catch((err) => {
      return res.status(400).json({ status: false, message: err.message });
    });
});

export default router;
