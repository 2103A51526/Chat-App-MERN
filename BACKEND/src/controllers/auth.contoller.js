import { generateToken } from "../lib/util.js";
import User from "../models/User.model.js";
import bcrypt from "bcryptjs";
import cloudinary from "../lib/cloudinary.js";

// Signup Controller
export const signup = async (req, res) => {
  const { fullName, email, password } = req.body;

  try {
    if (!fullName || !email || !password) {
      return res.status(400).json({ message: "All Field is required" });
    }
    // Password length validation
    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: "Password must be more then 6 character" });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password, salt);

    // Create new user
    const newUser = new User({
      fullName,
      email,
      password: hashPassword,
    });

    // Save user to DB
    await newUser.save();

    // Generate token and set cookie
    generateToken(newUser._id, res);

    // Send response
    res.status(201).json({
      _id: newUser._id,
      fullName: newUser.fullName,
      email: newUser.email,
    });
  } catch (error) {
    console.log("Error in signup controller", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Login Controller
export const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400)({ message: "Invalid credentials" });
    }
    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(400).json({ message: "invalid credential" });
    }

    generateToken(user._id, res);

    res.status(200).json({
      _id: user._id,
      fullName: user.email,
      profilePic: user.profilePic,
    });
  } catch (error) {
    console.log("Error in login controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

// Logout Controller
export const logout = (req, res) => {
  try {
    res.cookie("jwt", "", { httpOnly: true, expires: new Date(0) }); // safer & clearer
    res.status(200).json({ message: "Logged out Successfully" });
  } catch (error) {
    console.log("Error in logout Controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

// Update Profile
export const updateProfile = async (req, res) => {
  try {
    const { profilePic } = req.body;
    const userId = req.user._id;

    if (!profilePic) {
      return res.status(400).json({ message: "profile pic is required" });
    }
    const uploadResponse = await cloudinary.uploader.upload(profilePic);
    const updatedUser = await User.findByIdAnyUpdate(
      userId,
      { profilePic: uploadResponse.secure_url },
      { new: true }
    );
  } catch (error) {
    console.log("Error while updating profile", error);
    res.status(500).json({ message: "internal server error" });
  }
};

//check

export const checkAuth = (req, res) => {
  try {
    res.status(200).json(req.user);
  } catch (error) {
    console.log("Error in checkAuth controller", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};
