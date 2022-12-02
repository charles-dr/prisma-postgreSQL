import { PrismaClient } from "@prisma/client";
import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import * as routers from "./routes";

const prisma = new PrismaClient();
const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cors());

app.use("/users", routers.user);

app.listen(3000, () => {
  console.log("🚀 Sever ready at: http://localhost:3000");
});
