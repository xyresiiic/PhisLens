import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { analyzeEmail } from "./lib/scoring.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.post("/api/analyze", (req, res) => {
  try {
    const { raw } = req.body;
    if (!raw || typeof raw !== "string" || raw.trim().length === 0) {
      return res.status(400).json({ error: "No email content provided." });
    }
    const result = analyzeEmail(raw);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: "Failed to analyze email." });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`PhishLens running at http://localhost:${PORT}`);
});
