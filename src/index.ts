import { PrismaClient } from "@prisma/client";
import express from "express";
import bodyParser from "body-parser";
import cors from "cors";

const prisma = new PrismaClient();
const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cors());

app
  .route("/users")
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

app
  .route("/users/:id")
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

app.listen(3000, () => {
  console.log("🚀 Sever ready at: http://localhost:3000");
});
