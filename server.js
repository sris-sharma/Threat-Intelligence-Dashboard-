const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
// Home route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));


// Path to database
const dbPath = path.join(__dirname, 'db.json');

function readDB() {
  try {
    const raw = fs.readFileSync(dbPath, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    return { knownFraud: [], verifiedSafe: [] };
  }
}

// Phishing and scam keyword patterns
const SCAM_KEYWORDS = [
  'verify', 'verification', 'bank', 'login', 'signin', 'secure', 'security',
  'kyc', 'refund', 'support', 'helpdesk', 'prize', 'gift', 'bonus', 'reward',
  'lottery', 'cashback', 'crypto', 'wallet', 'suspend', 'urgent', 'free',
  'update-account', 'authenticate', 'billing', 'paytm', 'invoice'
];

// Abused / high-risk TLDs
const SUSPICIOUS_TLDS = ['.xyz', '.top', '.cc', '.info', '.work', '.click', '.buzz', '.fit', '.rest', '.gq', '.tk', '.ml'];

function analyzeLink(inputUrl) {
  const db = readDB();
  const rawInput = inputUrl.trim();
  const lower = rawInput.toLowerCase();

  // 1. Extract protocol & clean domain/hostname
  const hasHttp = lower.startsWith('http://');
  const hasHttps = lower.startsWith('https://');
  let cleanUrl = lower;

  if (hasHttp) {
    cleanUrl = lower.replace('http://', '');
  } else if (hasHttps) {
    cleanUrl = lower.replace('https://', '');
  }

  // Extract host (domain or IP without path/query)
  const host = cleanUrl.split('/')[0].split('?')[0].split(':')[0];

  // 2. Check Verified Safe list
  const isVerifiedSafe = db.verifiedSafe.some(safeDomain => {
    return host === safeDomain || host.endsWith('.' + safeDomain);
  });

  if (isVerifiedSafe) {
    return {
      url: rawInput,
      host,
      isFraud: false,
      status: 'Safe',
      riskScore: 5,
      indicators: {
        protocol: { label: 'Protocol', value: hasHttps ? 'HTTPS Encrypted' : 'Standard Web', isRisk: false },
        tld: { label: 'Domain Extension', value: '.' + host.split('.').pop(), isRisk: false },
        keywords: { label: 'Keywords', value: 'Clean', isRisk: false },
        database: { label: 'Reputation', value: 'Verified Whitelist', isRisk: false }
      },
      reasons: ['Verified legitimate domain from trusted safe list.']
    };
  }

  // 3. Check Known Fraud database
  const fraudMatch = db.knownFraud.find(item => {
    return lower.includes(item.pattern.toLowerCase());
  });

  if (fraudMatch) {
    return {
      url: rawInput,
      host,
      isFraud: true,
      status: 'Fraud',
      riskScore: fraudMatch.riskScore || 95,
      indicators: {
        protocol: { label: 'Protocol', value: hasHttp ? 'Insecure HTTP' : 'Unverified', isRisk: hasHttp },
        tld: { label: 'Domain Extension', value: '.' + host.split('.').pop(), isRisk: true },
        keywords: { label: 'Keywords', value: 'Flagged Pattern', isRisk: true },
        database: { label: 'Reputation', value: 'Known Threat Match', isRisk: true }
      },
      reasons: [
        `Matches known malicious threat database: ${fraudMatch.reason}.`
      ]
    };
  }

  // 4. Heuristic Analysis
  let riskScore = 10;
  const reasons = [];

  // Protocol Check
  let protocolRisk = false;
  let protocolValue = 'HTTPS Encrypted';
  if (hasHttp) {
    riskScore += 20;
    protocolRisk = true;
    protocolValue = 'Insecure HTTP';
    reasons.push('Uses insecure HTTP connection (no SSL encryption).');
  } else if (!hasHttps) {
    riskScore += 10;
    protocolRisk = true;
    protocolValue = 'No HTTPS Specified';
    reasons.push('No HTTPS protocol specified in the link.');
  }

  // Raw IP Check
  const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const isIp = ipRegex.test(host);
  if (isIp) {
    riskScore += 35;
    reasons.push('Uses a raw numerical IP address instead of a standard domain name.');
  }

  // TLD Check
  const matchedTld = SUSPICIOUS_TLDS.find(tld => host.endsWith(tld));
  const tldRisk = Boolean(matchedTld);
  if (matchedTld) {
    riskScore += 25;
    reasons.push(`Uses a frequently abused or high-risk domain extension (${matchedTld}).`);
  }

  // Keywords Check
  const matchedKeywords = SCAM_KEYWORDS.filter(kw => lower.includes(kw));
  const keywordRisk = matchedKeywords.length > 0;
  if (keywordRisk) {
    const penalty = Math.min(matchedKeywords.length * 20, 50);
    riskScore += penalty;
    reasons.push(`Contains high-risk scam/phishing keywords: "${matchedKeywords.slice(0, 4).join('", "')}".`);
  }

  // Hyphen count check
  const hyphenCount = (host.match(/-/g) || []).length;
  if (hyphenCount >= 2) {
    riskScore += 15;
    reasons.push(`Domain has multiple hyphens (${hyphenCount}), often used in brand impersonation.`);
  }

  // Length check
  if (host.length > 30) {
    riskScore += 10;
    reasons.push('Domain name is unusually long, often used to disguise fake URLs.');
  }

  riskScore = Math.min(Math.max(riskScore, 0), 99);

  let status = 'Safe';
  let isFraud = false;

  if (riskScore >= 70) {
    status = 'Fraud';
    isFraud = true;
  } else if (riskScore >= 35) {
    status = 'Suspicious';
    isFraud = false;
  } else {
    status = 'Safe';
    isFraud = false;
  }

  if (reasons.length === 0) {
    reasons.push('No common fraud patterns or malicious signatures detected.');
  }

  return {
    url: rawInput,
    host,
    isFraud,
    status,
    riskScore,
    indicators: {
      protocol: { label: 'Protocol', value: protocolValue, isRisk: protocolRisk },
      tld: { label: 'Domain Extension', value: matchedTld || ('.' + host.split('.').pop()), isRisk: tldRisk },
      keywords: { label: 'Phishing Signals', value: keywordRisk ? `${matchedKeywords.length} Detected` : 'None', isRisk: keywordRisk },
      database: { label: 'Reputation', value: isFraud ? 'Heuristic Threat' : 'Unlisted Clean', isRisk: isFraud }
    },
    reasons
  };
}

// Endpoints
app.post('/api/check', (req, res) => {
  const url = req.body.url || req.body.query;
  if (!url || typeof url !== 'string' || !url.trim()) {
    return res.status(400).json({ error: 'Please provide a valid website link or domain.' });
  }

  const result = analyzeLink(url);
  res.json(result);
});

app.get('/api/check', (req, res) => {
  const url = req.query.url;
  if (!url || typeof url !== 'string' || !url.trim()) {
    return res.status(400).json({ error: 'Please provide a ?url= query parameter.' });
  }

  const result = analyzeLink(url);
  res.json(result);
});
app.get('/', (req, res) => {
  res.send('LinkShield API is running successfully!');
});
app.listen(PORT, () => {
  console.log(`LinkShield website running at http://localhost:${PORT}`);
});
