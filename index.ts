import mongoose from 'mongoose';
import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import UserRoutes from './Route/userRoute'; 

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(cookieParser());

const PORT = process.env.PORT || 5000;
const MONGOURL = process.env.MONGOURL;

if (!MONGOURL) {
  throw new Error("MONGOURL is not defined");
}

mongoose
  .connect(MONGOURL)
  .then(() => {
    console.log("DB connected successfully");

    app.use('/api', UserRoutes);

    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  })
  .catch((error: Error) => {
    console.log("Error connecting to DB:", error.message);
  });
