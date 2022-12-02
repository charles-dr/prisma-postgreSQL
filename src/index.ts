import { PrismaClient } from "@prisma/client";
import express from "express";
import bodyParser from "body-parser";
import cors from "cors";

const prisma = new PrismaClient();
const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cors());

app.post("/users", async (req, res) => {
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

  console.log("[user.created]", created);

  return res.status(200).json(created);
});

app.listen(3000, () => {
  console.log("🚀 Sever ready at: http://localhost:3000");
});
