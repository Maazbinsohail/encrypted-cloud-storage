import express from "express";
import crypto from "crypto";
import multer from "multer";
import fs from "fs/promises";
import { Client } from "minio";
import axios from "axios";
import path from "path";

const dotenv = await import('dotenv');
dotenv.config({ path: "../.env" });

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

const minioClient = new Client({
  endPoint: process.env.MINIO_ENDPOINT || "localhost",
  port: Number(process.env.MINIO_PORT || 9000),
  useSSL: (process.env.MINIO_USE_SSL === "true") || false,
  accessKey: process.env.MINIO_ACCESS_KEY,
  secretKey: process.env.MINIO_SECRET_KEY,
});

async function ensureBucket(bucket) {
  try {
    const exists = await minioClient.bucketExists(bucket);
    if (!exists) await minioClient.makeBucket(bucket);
  } catch (e) {
    console.warn("MinIO bucket check failed:", e.message || e);
  }
}

function deriveKey() {
  if (!process.env.FILE_MASTER_KEY) throw new Error("Missing FILE_MASTER_KEY in env");
  return crypto.createHash("sha256").update(process.env.FILE_MASTER_KEY).digest();
}

function encryptBuffer(buffer) {
  const key = deriveKey();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  return { encrypted, iv: iv.toString("hex") };
}

function decryptBuffer(encryptedBuffer, ivHex) {
  const key = deriveKey();
  const iv = Buffer.from(ivHex, "hex");
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  return Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
}

async function virusTotalCheck(hash) {
  if (!process.env.VT_API_KEY) return { error: "2fe8da515d517d22c06b60ac543c760949ad8c4a34e2edc3337c393054c13a91" };
  try {
    const res = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: { "x-apikey": process.env.VT_API_KEY },
      timeout: 10000,
    });
    return res.data;
  } catch (err) {
    if (err.response && err.response.status === 404) return { not_found: true };
    return { error: "VT lookup failed", details: err.message || err.toString() };
  }
}

async function osintCheck(hash) {
  try {
    const payload = new URLSearchParams();
    payload.append("query", "get_info");
    payload.append("hash", hash);

    const res = await axios.post("https://mb-api.abuse.ch/api/v1/", payload.toString(), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      timeout: 10000,
    });
    return res.data;
  } catch (err) {
    return { error: "OSINT lookup failed", details: err.message || err.toString() };
  }
}

async function generateSummary(text) {
  if (!process.env.OPENAI_API_KEY || !process.env.OPENAI_MODEL) return "AI not configured";
  try {
    const resp = await axios.post("https://api.openai.com/v1/chat/completions", {
      model: process.env.OPENAI_MODEL,
      messages: [
        { role: "system", content: "Summarize the file metadata and likely contents." },
        { role: "user", content: text }
      ],
      max_tokens: 300,
      temperature: 0.0,
    }, {
      headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}`, "Content-Type": "application/json" },
      timeout: 15000,
    });
    return resp.data.choices?.[0]?.message?.content || "AI returned no text";
  } catch (err) {
    return `AI failed: ${err.message || err.toString()}`;
  }
}

router.post("/upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const bucket = process.env.MINIO_BUCKET || "ecs-bucket";
    await ensureBucket(bucket);

    const fileBuf = req.file.buffer;
    const sha256 = crypto.createHash("sha256").update(fileBuf).digest("hex");

    const { encrypted, iv } = encryptBuffer(fileBuf);

    const objectName = `${Date.now()}-${path.basename(req.file.originalname)}.enc`;

    await minioClient.putObject(bucket, objectName, encrypted, {
      'x-amz-meta-original-filename': req.file.originalname,
      'x-amz-meta-iv': iv,
      'x-amz-meta-sha256': sha256,
    });

    const [vt, osint, aiSummary] = await Promise.all([
      virusTotalCheck(sha256),
      osintCheck(sha256),
      generateSummary(`File name: ${req.file.originalname}\nSHA256: ${sha256}`),
    ]);

    res.json({
      status: "success",
      sha256,
      minio_file: objectName,
      minio_bucket: bucket,
      vt,
      osint,
      aiSummary,
      note: "No DB; file key derived from FILE_MASTER_KEY.",
    });
  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).json({ error: err.message || err.toString() });
  }
});

router.get("/decrypt/:object", async (req, res) => {
  try {
    const bucket = process.env.MINIO_BUCKET || "ecs-bucket";
    const objectName = req.params.object;
    const stat = await minioClient.statObject(bucket, objectName);
    const iv = stat.metaData && (stat.metaData['x-amz-meta-iv'] || stat.metaData['X-Amz-Meta-Iv']);
    if (!iv) return res.status(400).json({ error: "IV not found in metadata" });
    const stream = await minioClient.getObject(bucket, objectName);
    const chunks = [];
    for await (const c of stream) chunks.push(c);
    const encryptedBuffer = Buffer.concat(chunks);
    const decrypted = decryptBuffer(encryptedBuffer, iv);
    res.setHeader("Content-Disposition", `attachment; filename="${stat.metaData['x-amz-meta-original-filename'] || 'file' }"`);
    res.send(decrypted);
  } catch (err) {
    console.error("Decrypt error:", err);
    res.status(500).json({ error: err.message || err.toString() });
  }
});

export default router;