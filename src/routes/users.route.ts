import { Router } from "express";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();
const router = Router();

router
  .route("/")
  .post(async (req, res) => {
    const { email, name } = req.body;

    if (!email) {
      return res.status(400).json({
        status: false,
        message: "email is required",
      });
    }

    const userWithEmail = await prisma.user.findUnique({ where: { email } });
    if (userWithEmail) {
      return res.status(400).json({
        status: false,
        message: "User already exists with email",
      });
    }

    const created = await prisma.user.create({
      data: { email, name },
    });

    return res.status(200).json(created);
  })
  .get(async (req, res) => {
    const users = await prisma.user.findMany();
    res.status(200).json(users);
  });

router
  .route("/:id")
  .get(async (req, res) => {
    const userId = parseInt(req.params.id, 10);
    return prisma.user
      .findUnique({ where: { id: userId } })
      .then((user: any) => res.status(200).json(user));
  })
  .patch(async (req, res) => {
    const userId = parseInt(req.params.id, 10);
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      return res
        .status(400)
        .json({ status: false, message: "Not found the user!" });
    }

    const { email, name } = req.body;
    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: { email, name },
    });

    return res.status(200).json(updatedUser);
  });

export default router;
