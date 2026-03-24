const express = require("express");
const multer = require("multer");
const cors = require("cors");
const fs = require("fs");
const mammoth = require("mammoth");
const pdfParse = require("pdf-parse");

const app = express();
app.use(cors());
app.use(express.json());

let totalRequests = 0;
let requestCount = 0;

// 🔥 RATE LIMITING
app.use((req, res, next) => {
    requestCount++;

    if (requestCount > 100) {
        return res.status(429).json({
            error: "Too many requests. Try again later."
        });
    }

    next();
});

const upload = multer({ dest: "uploads/" });

// 🔹 Extract text
async function extractText(file) {
    const buffer = fs.readFileSync(file.path);

    if (file.mimetype === "text/plain") return buffer.toString();

    if (file.mimetype === "application/pdf") {
        const data = await pdfParse(buffer);
        return data.text || "";
    }

    if (file.mimetype.includes("word")) {
        const result = await mammoth.extractRawText({ buffer });
        return result.value || "";
    }

    return "";
}

// 🔥 CHUNK PROCESSING
function processChunks(text, chunkSize = 500) {
    let chunks = [];
    let lines = text.split("\n");

    for (let i = 0; i < lines.length; i += chunkSize) {
        chunks.push(lines.slice(i, i + chunkSize).join("\n"));
    }

    return chunks;
}

// 🔥 Risk Score
function getRiskScore(summary) {
    let score = 0;
    score += summary.passwords * 5;
    score += summary.apiKeys * 4;
    score += summary.tokens * 4;
    score += summary.errors * 1;
    return Math.min(score, 10);
}

// 🔥 Analyzer (per chunk)
function analyzeLogs(text) {
    const lines = text.split("\n");

    let emails = 0, passwords = 0, apiKeys = 0, errors = 0, tokens = 0;
    let findings = [];
    let maskedLogs = [];

    const emailRegex = /\S+@\S+\.\S+/;
    const passwordRegex = /password\s*[:=]\s*\S+/i;
    const apiKeyRegex = /(api[_-]?key)\s*[:=]\s*\S+/i;
    const tokenRegex = /Bearer\s+[A-Za-z0-9\-\._]+/i;
    const errorRegex = /error|exception/i;

    lines.forEach((line, index) => {
        let mod = line;

        if (emailRegex.test(line)) {
            const val = line.match(emailRegex)[0];
            emails++;
            mod = mod.replace(emailRegex, "****@****.com");

            findings.push({ type: "email", value: val, risk: "low", line: index + 1 });
        }

        if (passwordRegex.test(line)) {
            const val = line.split(/[:=]/)[1];
            passwords++;
            mod = mod.replace(passwordRegex, "password=****");

            findings.push({ type: "password", value: val.trim(), risk: "critical", line: index + 1 });
        }

        if (apiKeyRegex.test(line)) {
            const val = line.split(/[:=]/)[1];
            apiKeys++;
            mod = mod.replace(apiKeyRegex, "apiKey=****");

            findings.push({ type: "api_key", value: val.trim(), risk: "high", line: index + 1 });
        }

        if (tokenRegex.test(line)) tokens++;
        if (errorRegex.test(line)) errors++;

        maskedLogs.push(mod);
    });

    let risk = "Low";
    if (passwords > 0) risk = "Critical";
    else if (apiKeys > 0 || tokens > 0) risk = "High";

    return {
        summary: { emails, passwords, apiKeys, tokens, errors, risk },
        findings,
        maskedLogs
    };
}

// 🔥 MERGE RESULTS FROM CHUNKS
function mergeResults(results) {
    let merged = {
        emails: 0,
        passwords: 0,
        apiKeys: 0,
        tokens: 0,
        errors: 0,
        risk: "Low"
    };

    let allFindings = [];
    let allLogs = [];

    results.forEach(r => {
        merged.emails += r.summary.emails;
        merged.passwords += r.summary.passwords;
        merged.apiKeys += r.summary.apiKeys;
        merged.tokens += r.summary.tokens;
        merged.errors += r.summary.errors;

        allFindings.push(...r.findings);
        allLogs.push(...r.maskedLogs);
    });

    if (merged.passwords > 0) merged.risk = "Critical";
    else if (merged.apiKeys > 0) merged.risk = "High";

    return {
        summary: merged,
        findings: allFindings,
        maskedLogs: allLogs
    };
}

// 🔥 Insights
function generateInsights(summary) {
    let insights = [];

    if (summary.apiKeys > 0) insights.push("API key exposed in logs");
    if (summary.passwords > 0) insights.push("Passwords detected in logs (critical risk)");
    if (summary.errors > 0) insights.push("System errors detected");

    return insights;
}

// 🔥 Policy
function getPolicyAction(risk) {
    if (risk === "Critical") return "BLOCK: Sensitive data exposure detected";
    if (risk === "High") return "MASK: Hide sensitive information";
    return "ALLOW: No issues";
}

// 🔹 ROUTE
app.post("/analyze", upload.single("file"), async (req, res) => {
    const start = Date.now();
    totalRequests++;

    try {
        let text = req.body.content || "";

        if (req.file) {
            text = await extractText(req.file);
            fs.unlinkSync(req.file.path);
        }

        if (!text) return res.status(400).json({ error: "No input" });

        // 🔥 CHUNK PROCESSING
        const chunks = processChunks(text);
        const results = chunks.map(chunk => analyzeLogs(chunk));
        const finalResult = mergeResults(results);

        const insights = generateInsights(finalResult.summary);
        const risk_score = getRiskScore(finalResult.summary);
        const action = getPolicyAction(finalResult.summary.risk);

        const analysis_time = Date.now() - start;

        res.json({
            success: true,
            data: {
                summary: "Log contains sensitive credentials and system errors",
                findings: finalResult.findings,
                risk_score,
                risk_level: finalResult.summary.risk,
                insights,
                action,
                maskedLogs: finalResult.maskedLogs,
                analysis_time,
                total_requests: totalRequests
            }
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: "Server error" });
    }
});

app.listen(5000, () => {
    console.log("Server running on http://localhost:5000");
});