import dotenv from "dotenv";
dotenv.config({ path: "./.env" });

import express from "express";
import cors from "cors";
import fileRoutes from "./routes/file.js";
import path from "path";

console.log("ENV TEST MINIO_ENDPOINT:", process.env.MINIO_ENDPOINT);

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/", (req, res) => res.send("Backend running"));

app.use("/api/files", fileRoutes);

const clientPath = path.resolve("../client/dist");
app.use(express.static(clientPath));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server listening on ${PORT}`));