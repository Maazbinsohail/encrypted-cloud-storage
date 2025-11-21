#!/usr/bin/env node
import dotenv from "dotenv";
dotenv.config({ path: "./.env" });

import Minio from "minio";
import crypto from "crypto";
import fs from "fs/promises";
import process from "process";

const [,, bucket, objectName, outputPath] = process.argv;
if (!bucket || !objectName || !outputPath) {
  console.error("Usage: node decrypt.js <bucket> <objectName> <outputPath>");
  process.exit(2);
}

const client = new Minio.Client({
  endPoint: process.env.MINIO_ENDPOINT || "localhost",
  port: Number(process.env.MINIO_PORT || 9000),
  useSSL: (process.env.MINIO_USE_SSL === "true") || false,
  accessKey: process.env.MINIO_ACCESS_KEY,
  secretKey: process.env.MINIO_SECRET_KEY,
});

function deriveKey() { return crypto.createHash("sha256").update(process.env.FILE_MASTER_KEY).digest(); }
function decryptBuffer(encryptedBuffer, ivHex) {
  const iv = Buffer.from(ivHex, "hex");
  const key = deriveKey();
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  return Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
}

async function run() {
  try {
    const stat = await client.statObject(bucket, objectName);
    const iv = stat.metaData && (stat.metaData['x-amz-meta-iv'] || stat.metaData['X-Amz-Meta-Iv']);
    if (!iv) throw new Error("IV metadata not found");
    const stream = await client.getObject(bucket, objectName);
    const chunks = [];
    for await (const c of stream) chunks.push(c);
    const encryptedBuffer = Buffer.concat(chunks);
    const decrypted = decryptBuffer(encryptedBuffer, iv);
    await fs.writeFile(outputPath, decrypted);
    console.log("Decrypted to", outputPath);
  } catch (e) {
    console.error("Decrypt failed:", e);
    process.exit(1);
  }
}

run();