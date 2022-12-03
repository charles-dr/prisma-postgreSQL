import express from "express";
import path from "path";
import bodyParser from "body-parser";
import cors from "cors";
import * as dotenv from "dotenv";
import session from "express-session";
import * as passportConfig from "./config/passport";
import * as routers from "./routes";

dotenv.config();

const app = express();

app.use(express.static(path.join(__dirname, "../public")));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cors());
app.use(
  session({
    secret: "keyboard-cat",
    resave: true,
    saveUninitialized: true,
  })
);

passportConfig.configure(app);

app.use("/users", routers.user);
app.use("/posts", routers.post);
app.use("/auth", routers.auth);

app.use((req, res, next) => {
  return res.status(404).send("Not found or invalid params");
});

app.listen(3000, () => {
  console.log("🚀 Server ready at: http://localhost:3000");
});
