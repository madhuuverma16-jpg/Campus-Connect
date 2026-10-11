import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/User.js";

/* REGISTER USER */
export const register = async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      password,
      picturePath,
      friends,
      location,
      occupation,
    } = req.body;
    const normalizedEmail =
      typeof email === "string" ? email.trim().toLowerCase() : "";

    if (!normalizedEmail || typeof password !== "string" || !password) {
      return res.status(400).json({ msg: "Email and password are required." });
    }

    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      return res
        .status(500)
        .json({ msg: "Server configuration error: JWT_SECRET is missing." });
    }

    const salt = await bcrypt.genSalt();
    const passwordHash = await bcrypt.hash(password, salt);

    const newUser = new User({
      firstName,
      lastName,
      email: normalizedEmail,
      password: passwordHash,
      picturePath,
      friends,
      location,
      occupation,
      viewedProfile: Math.floor(Math.random() * 10000),
      impressions: Math.floor(Math.random() * 10000),
    });
    const savedUser = await newUser.save();
    const publicUser = savedUser.toObject();
    delete publicUser.password;
    const token = jwt.sign({ id: savedUser._id }, jwtSecret);
    res.status(201).json({ token, user: publicUser });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/* LOGGING IN */
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const normalizedEmail =
      typeof email === "string" ? email.trim().toLowerCase() : "";
    const jwtSecret = process.env.JWT_SECRET;

    if (!normalizedEmail || typeof password !== "string" || !password) {
      return res.status(400).json({ msg: "Email and password are required." });
    }

    if (!jwtSecret) {
      return res
        .status(500)
        .json({ msg: "Server configuration error: JWT_SECRET is missing." });
    }

    const user = await User.findOne({ email: normalizedEmail });
    if (!user) return res.status(400).json({ msg: "User does not exist. " });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: "Invalid credentials. " });

    const token = jwt.sign({ id: user._id }, jwtSecret);
    const publicUser = user.toObject();
    delete publicUser.password;
    res.status(200).json({ token, user: publicUser });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
