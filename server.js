const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const User = require("./model/user");
const jwt = require("jsonwebtoken");

const JWT_SECRET =
  "HHJ5JHG34UK4JKHKVG2CFG1X21H2BL1H-$#%$vhvHFGFGHFHG-XXFXFG4345VHJVHJ";

mongoose.connect(
  "mongodb+srv://login-app:j9PVaLSDDDbtTv8l@login-app.jw1jq.mongodb.net/myFirstDatabase?retryWrites=true&w=majority",
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  }
);

const port = process.env.PORT || 5000;
const app = express();
app.use("/", express.static(path.join(__dirname, "static")));
app.use(bodyParser.json());

app.post("/api/change-password", async (req, res) => {
  const { token, newpassword: plainTextPassword } = req.body;

  if (!plainTextPassword || typeof plainTextPassword !== "string") {
    return res.json({ status: "error", error: "Invalid username" });
  }

  if (plainTextPassword.length < 5) {
    return res.json({
      status: "error",
      error: "Password must be 6 characters or long",
    });
  }

  try {
    const user = jwt.verify(token, JWT_SECRET);

    const _id = user.id;

    const password = await bcrypt.hash(plainTextPassword, 10);
    await User.updateOne(
      { _id },
      {
        $set: { password },
      }
    );
    res.json({ status: "ok" });
  } catch (error) {
    console.log(error);
    res.json({ status: "error", error: "Unkown user error!!" });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username }).lean();

  if (!user) {
    return res.json({
      status: "error",
      error: "Invalid username and password",
    });
  }

  if (await bcrypt.compare(password, user.password)) {
    const token = jwt.sign(
      { id: user._id, username: user.username },
      JWT_SECRET
    );

    return res.json({ status: "ok", data: token });
  }

  res.json({ status: "error", error: "Invalid username and password" });
});

app.post("/api/register", async (req, res) => {
  const { username, password: plainTextPassword } = req.body;
  if (!username || typeof username !== "string") {
    return res.json({ status: "error", error: "Invalid username" });
  }

  if (!plainTextPassword || typeof plainTextPassword !== "string") {
    return res.json({ status: "error", error: "Invalid username" });
  }

  if (plainTextPassword.length < 5) {
    return res.json({
      status: "error",
      error: "Password must be 6 characters or long",
    });
  }

  const password = await bcrypt.hash(plainTextPassword, 10);
  try {
    const userResponse = await User.create({
      username,
      password,
    });

    console.log("User created successfully: ", userResponse);
  } catch (error) {
    if (error.code === 11000) {
      return res.json({ status: "error", error: "Username already exists!" });
    }
    throw error;
  }
  res.json({ status: "ok" });
});

app.listen(port, () => {
  console.log(`Server is up on PORT: ${port}`);
});
