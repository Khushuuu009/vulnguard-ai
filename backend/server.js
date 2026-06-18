// backend/server.js
import express from 'express';
import cors from 'cors';
import { exec } from 'child_process';
import { promisify } from 'util';
import { writeFileSync, unlinkSync, existsSync, mkdirSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const execAsync = promisify(exec);
const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Ensure temp directory exists
const tempDir = path.join(__dirname, 'temp');
if (!existsSync(tempDir)) {
  mkdirSync(tempDir);
}

app.post('/api/scan', async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) {
      return res.status(400).json({ error: 'No code provided' });
    }

    // Write Solidity code to a temporary file
    const tempFile = path.join(tempDir, `contract_${Date.now()}.sol`);
    writeFileSync(tempFile, code);

    // Path to the Python scanner (now at ../ml/vulnguard.py)
    const pythonScript = path.join(__dirname, '..', 'ml', 'vulnguard.py');

    // Execute the Python scanner
    const { stdout, stderr } = await execAsync(`python "${pythonScript}" "${tempFile}"`);

    // Clean up temp file
    unlinkSync(tempFile);

    if (stderr) {
      console.error('Python stderr:', stderr);
    }

    // Parse the JSON output from Python
    const result = JSON.parse(stdout);
    res.json(result);
  } catch (error) {
    console.error('Error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`🚀 VulnGuard API running on http://localhost:${PORT}`);
});