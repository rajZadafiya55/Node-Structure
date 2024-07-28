import fs from "fs";
import path from "path";

fs.writeFileSync(
  "./npm.txt",
  `
  {
  "name": "projectName",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "type": "module",
  "scripts": {
    "dev": "nodemon -r dotenv/config src/index.js"
  },
  "author": "",
  "license": "ISC",
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "cloudinary": "^2.2.0",
    "cloudinary-build-url": "^0.2.4",
    "cookie-parser": "^1.4.6",
    "cors": "^2.8.5",
    "dotenv": "^16.4.5",
    "express": "^4.19.2",
    "jsonwebtoken": "^9.0.2",
    "mongoose": "^8.4.5",
    "mongoose-aggregate-paginate-v2": "^1.1.1",
    "multer": "^1.4.5-lts.1"
  },
  "devDependencies": {
    "nodemon": "^3.1.4"
  }
}

  `
);

// .env =================================

fs.writeFileSync(
  "./.env",
  `
DB_URI=
PORT=4000



ACCESS_TOKEN_SECRET=
ACCESS_TOKEN_EXPIRY=1d
REFRESH_TOKEN_SECRET=
REFRESH_TOKEN_EXPIRY=10d



CLOUDINARY_CLOUD_NAME=
CLOUDINARY_API_KEY=
CLOUDINARY_API_SCREAT=
`
);

// Define the base directory and the folders to be created
const baseDir = "./src";
const folders = [
  "controllers",
  "db",
  "middlewares",
  "models",
  "routes",
  "utils",
];
const files = ["app.js", "index.js"];

// Create the 'src' folder if it doesn't exist
if (!fs.existsSync(baseDir)) {
  fs.mkdirSync(baseDir);
}

// Create the specified folders inside the 'src' folder
folders.forEach((folder) => {
  const folderPath = path.join(baseDir, folder);
  if (!fs.existsSync(folderPath)) {
    fs.mkdirSync(folderPath);
  }
});

// Create the specified files inside the 'src' folder
files.forEach((file) => {
  const filePath = path.join(baseDir, file);
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, "");
  }
});

// Define the content for each file
const fileContents = {
  "controllers/user.controller.js": `
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { ApiResponse } from "../utils/ApiRespone.js";
import jwt from "jsonwebtoken";

async function generateAccessAndRefreshTokens(userId) {
  try {
    const user = await User.findById(userId);
    const accessToken = user.accessTokenGenerator();
    const refreshToken = user.refreshTokenGenerator();

    user.refreshToken = refreshToken;

    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "failed to generate Access And RefreshTokens " + error
    );
  }
}

export const registration = asyncHandler(async (req, res) => {
  const { email, userName, fullName, password } = req.body;

  // Check if any required field is empty
  if (
    [email, userName, fullName, password].some(
      (field) => !field || field.trim() === ""
    )
  ) {
    throw new ApiError(400, "All fields are required");
  }

  // Check if user already exists with the same username
  const existingUser = await User.findOne({
    $or: [{ userName }, { email }],
  });

  if (existingUser) {
    if (existingUser.email === email) {
      throw new ApiError(400, "Email address is already registered");
    } else {
      throw new ApiError(400, "Username is already taken");
    }
  }

  // Create the new user
  const newUser = await User.create({
    email,
    userName: userName.toLowerCase(), // Ensure username is stored in lowercase
    fullName,
    password,
  });

  // Select fields to return in the response
  const user = await User.findById(newUser._id).select(
    "-password -refreshToken"
  );

  // Check if user was successfully created
  if (!user) {
    throw new ApiError(500, "Something went wrong while registering the user");
  }

  // Respond with success message and user details
  res
    .status(200)
    .json(new ApiResponse(200, user, "User registration successful"));
});

export const login = asyncHandler(async (req, res) => {
  const { userName, email, password } = req.body;

  if ((!userName || !email) && !password) {
    throw new ApiError(400, "userName and password is require");
  }

  const user = await User.findOne({
    $or: [{ userName }, { email }],
  });

  if (!user) {
    throw new ApiError(404, "User does not exist");
  }

  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    throw new ApiError(400, "Incorrect password");
  }

  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    user._id
  );

  console.log(refreshToken);
  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  const options = {
    httpOnly: true,
    secure: true, // not modifiable
  };

  res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        { loggedInUser, accessToken, refreshToken },
        "user login successfully"
      )
    );
});

export const logout = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $unset: {
        refreshToken: 1,
      },
    },
    {
      new: true,
    }
  );

  const options = {
    httpOnly: true,
    secure: true, // not modifiable
  };

  res
    .status(200)
    .clearCookie("refreshToken", options)
    .clearCookie("accessToken", options)
    .json(new ApiResponse(200, {}, "user logout successfully"));
});

export const generateRefreshToken = asyncHandler(async (req, res) => {
  const oldRefreshToken = req.cookies?.refreshToken || req.user.refreshToken;

  if (!oldRefreshToken) {
    throw new ApiError(401, "unauthorized request");
  }

  try {
    const userId = jwt.verify(
      oldRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    if (!userId) {
      throw new ApiError(501, "user Id not found");
    }

    const user = await User.findById(userId?._id);

    if (user?.refreshToken !== oldRefreshToken) {
      throw new ApiError(401, "Refresh token is expired or used");
    }

    const { accessToken, newRefreshToken } =
      await generateAccessAndRefreshTokens(user._id);

    const options = {
      httpOnly: true,
      secure: true,
    };

    res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access Token refreshed Successfully"
        )
      );
  } catch (error) {
    throw new ApiError(401, "JWT token is expired"+ error);
  }
});

export const userDataChange = asyncHandler(async (req, res) => {
  const { userName, email, fullName } = req.body;

  if (!(userName || email || fullName)) {
    throw new ApiError(401, "field are required");
  }

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        userName,
        email,
        fullName,
      },
    },
    { new: true }
  ).select("-password -refreshToken");

  res
    .status(200)
    .json(new ApiResponse(200, user, "user data updated successfully"));
});

export const changePassword = asyncHandler(async (req, res) => {
  const { email, userName, oldPassword, newPassword } = req.body;

  if (!(email || userName) && !password && !newPassword) {
    throw new ApiError(400, "all field are required");
  }

  const user = await User.findOne({
    $or: [{ email }, { userName }],
  });

  if (!user) {
    throw new ApiError(400, "user not exist");
  }

  const passwordCorrect = await user.isPasswordCorrect(oldPassword);

  if (!passwordCorrect) {
    throw new ApiError(400, "password not valid");
  }

  user.password = newPassword;
  await user.save({ validateBeforeSave: false });

  res
    .status(200)
    .json(new ApiResponse(200, {}, "password updated successfully"));
});

`.trim(),
  "db/index.js": `
import mongoose from "mongoose";

const dbConnect = async () => {
  try {
    await mongoose.connect(process.env.DB_URI);
    console.log("MongoDb connect successfully...");
  } catch (error) {
    console.log("MongoDb Failed to connect...:", error);
  }
};

export { dbConnect };
`.trim(),
  "middlewares/auth.middleware.js": `
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";

export const verifyJWT = asyncHandler(async (req, res, next) => {
  try {
    const accessToken = req.cookies?.accessToken;
    if (!accessToken) {
      throw new ApiError(500, "accessToken not found");
    }

    const userData = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);

    if (!userData) {
      throw new ApiError(500, "userData not found");
    }
    const user = await User.findById(userData._id);

    if (!user) {
      throw new ApiError(400, "unauthorized request");
    }

    req.user = user;
    next();
  } catch (error) {
    throw new ApiError(400, \`verifyJWT failed \${error?.massage}\`);
  }
});
`.trim(),
  "middlewares/multer.middleware.js": `
import multer from "multer";

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "./public/temp");
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  },
});

export const upload = multer({
  storage,
});
`.trim(),
  "models/user.model.js": `
import mongoose from "mongoose";
import bcryptjs from "bcryptjs";
import jwt from "jsonwebtoken";

var userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
    },
    userName: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      index: true,
    },
    fullName: {
      type: String,
      required: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
    },
    refreshToken: {
      type: String,
    },
  },
  { timestamps: true }
);

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }
  this.password = await bcryptjs.hash(this.password, 10);
  next();
});

userSchema.methods.isPasswordCorrect = async function (password) {
  return await bcryptjs.compare(password, this.password);
};

userSchema.methods.accessTokenGenerator = function () {
  return jwt.sign(
    {
      _id: this._id,
      userName: this.userName,
      email: this.email,
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
    }
  );
};

userSchema.methods.refreshTokenGenerator = function () {
  return jwt.sign(
    {
      _id: this._id,
      userName: this.userName,
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
    }
  );
};

export const User = mongoose.model("User", userSchema);
`.trim(),
  "routes/user.route.js": `
import { Router } from "express";
import {
  changePassword,
  generateRefreshToken,
  login,
  logout,
  registration,
  userDataChange,
} from "../controllers/user.controller.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

export const user = Router();

user.route("/register").post(registration);
user.route("/login").post(login);
user.route("/logout").post(verifyJWT, logout);
user.route("/generateRefreshToken").post(verifyJWT, generateRefreshToken);
user.route("/user-data-change").patch(verifyJWT, userDataChange);
user.route("/password-change").patch(changePassword);
`.trim(),

  "utils/ApiError.js": `
class ApiError extends Error {
  constructor(statuscode, massage = "something went wrong", errors = []) {
    super(massage);
    this.statuscode = statuscode;
    this.massage = massage;
    this.data = null;
    this.errors = errors;
    this.success = false;
  }
}

export { ApiError };
`.trim(),
  "utils/ApiRespone.js": `
class ApiResponse {
  constructor(statuscode, data, massage = "success") {
    this.statuscode = statuscode;
    this.data = data;
    this.massage = massage;
    this.success = statuscode < 400;
  }
}

export { ApiResponse };
`.trim(),
  "utils/asyncHandler.js": `
const asyncHandler = (requestHandler) => {
  return (req, res, next) => {
    Promise.resolve(requestHandler(req, res, next)).catch((err) => next(err));
  };
};

export { asyncHandler };
`.trim(),
  "utils/cloudinary.js": `
import { v2 as cloudinary } from "cloudinary";
import { extractPublicId } from "cloudinary-build-url";
import fs from "fs";

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SCREAT,
});

const uploadOnCloudinary = async (localFilePath) => {
  try {
    if (!localFilePath) return null;
    const response = await cloudinary.uploader.upload(localFilePath, {
      resource_type: "auto",
    });
    fs.unlinkSync(localFilePath);
    return response;
  } catch (error) {
    fs.unlinkSync(localFilePath);
    return null;
  }
};

const deleteCloudniary = async (publicId, resource_type) => {
  try {
    if (!publicId) return null;
    const res = await cloudinary.uploader.destroy(publicId, {
      resource_type: '${"resource_type"}',
    });
    return res;
  } catch (error) {
    console.error("Error deleting image from Cloudinary:", error);
    return null;
  }
};

const deleteUserCloudniary = async (url, resourceType = "image") => {
  const public_id = extractPublicId(url);
  try {
    const response = await cloudinary.uploader.destroy(public_id, {
      resource_type: resourceType,
    });
    return response;
  } catch (error) {
    console.log(error);
  }
};

export { uploadOnCloudinary, deleteCloudniary, deleteUserCloudniary };

`.trim(),
  "app.js": `
import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";

const app = express();

app.use(cookieParser());
app.use(cors());

app.use(
  express.json({
    limit: "16kb",
  })
);
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.status(200).json("welcome to instagram");
});

// route import
import { user } from "./routes/user.route.js";

//use routes

app.use("/api/v1/users", user);

export { app };
`.trim(),
  "index.js": `
import { app } from "./app.js";
import { dbConnect } from "./db/index.js";
import dotenv from "dotenv";

dotenv.config({
  path: "./.env",
});

const PORT = process.env.PORT || 3000;

dbConnect()
  .then(() => {
    app.on("error", (error) => {
      console.log("server connection error...", error);
    });
    app.listen(PORT, () => {
      console.log(\`server running on PORT \${PORT}...\`);
    });
  })
  .catch((error) => {
    console.log("index.js file error :", error);
  });
`.trim(),
};

// Write the content to each file
Object.keys(fileContents).forEach((filePath) => {
  const fullPath = path.join(baseDir, filePath);
  const folderPath = path.dirname(fullPath);
  if (!fs.existsSync(folderPath)) {
    fs.mkdirSync(folderPath, { recursive: true });
  }
  fs.writeFileSync(fullPath, fileContents[filePath]);
});

console.log("Folders and files created successfully!");
