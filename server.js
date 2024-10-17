const express = require("express");
const dotenv = require("dotenv");
const connectDB = require("./config/db");
const userRoutes = require("./routes/userRoutes");
const cors = require("cors");

const app = express();


dotenv.config();


app.use(express.json());
app.use(cors());


connectDB();


app.use("/api/users", userRoutes);


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server is running at port ${PORT}`));
