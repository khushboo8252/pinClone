import {User} from "../models/userModel.js";
import bcrypt from "bcryptjs";
import TryCatch from "../utils/TryCatch.js";
import generateToken from "../utils/generateToken.js";

// Register a new user
export const registerUser = TryCatch(async (req, res) => {
  const { name, email, password } = req.body;

  // Check if user already exists
  let user = await User.findOne({ email });

  if (user) {
    return res.status(400).json({ message: "Already have an account with this email" });
  }

  // Hash the user's password
  const hashPassword = await bcrypt.hash(password, 10);

  // Create and save the new user
  user = await User.create({
    name,
    email,
    password: hashPassword,
  });

  // Generate token for the user
  generateToken(user._id, res);

  res.status(201).json({
    user,
    message: "User Registered",
  });
});

// Log in a user
export const loginUser = TryCatch(async (req, res) => {
  const { email, password } = req.body;

  // Find the user by email
  const user = await User.findOne({ email });

  if (!user) {
    return res.status(400).json({ message: "No user with this email" });
  }

  // Compare the provided password with the stored hash
  const isPasswordCorrect = await bcrypt.compare(password, user.password);

  if (!isPasswordCorrect) {
    return res.status(400).json({ message: "Wrong password" });
  }

  // Generate token for the user
  generateToken(user._id, res);

  res.json({
    user,
    message: "Logged in",
  });
});

// Get the profile of the logged-in user
export const myProfile = TryCatch(async (req, res) => {
  const user = await User.findById(req.user._id);
  res.json(user);
});

// Get the profile of a user by their ID
export const userProfile = TryCatch(async (req, res) => {
  const user = await User.findById(req.params.id).select("-password");
  res.json(user);
});

// Follow or unfollow a user
export const followAndUnfollowUser = TryCatch(async (req, res) => {
  const user = await User.findById(req.params.id);
  const loggedInUser = await User.findById(req.user._id);

  if (!user) {
    return res.status(400).json({ message: "No user with this ID" });
  }

  if (user._id.toString() === loggedInUser._id.toString()) {
    return res.status(400).json({ message: "You can't follow yourself" });
  }

  if (user.followers.includes(loggedInUser._id)) {
    const indexFollowing = loggedInUser.following.indexOf(user._id);
    const indexFollowers = user.followers.indexOf(loggedInUser._id);

    loggedInUser.following.splice(indexFollowing, 1);
    user.followers.splice(indexFollowers, 1);

    await loggedInUser.save();
    await user.save();

    res.json({ message: "User Unfollowed" });
  } else {
    loggedInUser.following.push(user._id);
    user.followers.push(loggedInUser._id);

    await loggedInUser.save();
    await user.save();

    res.json({ message: "User followed" });
  }
});

// Log out a user
export const logOutUser = TryCatch(async (req, res) => {
  res.cookie("token", "", { maxAge: 0 });
  res.json({ message: "Logged Out Successfully" });
});
