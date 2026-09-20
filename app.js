// LinkShield — Website Client Script

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('check-form');
  const input = document.getElementById('link-input');
  const loading = document.getElementById('loading');
  const resultBox = document.getElementById('result-box');
  const resultUrl = document.getElementById('result-url');
  const resultBadge = document.getElementById('result-badge');
  const scoreText = document.getElementById('score-text');
  const progressBarFill = document.getElementById('progress-bar-fill');
  const gaugeHint = document.getElementById('gauge-hint');
  const reasonsList = document.getElementById('reasons-list');
  const sampleButtons = document.querySelectorAll('.sample-btn');

  // Indicators
  const indProtocol = document.getElementById('ind-protocol');
  const valProtocol = document.getElementById('val-protocol');
  const indTld = document.getElementById('ind-tld');
  const valTld = document.getElementById('val-tld');
  const indKeywords = document.getElementById('ind-keywords');
  const valKeywords = document.getElementById('val-keywords');
  const indDatabase = document.getElementById('ind-database');
  const valDatabase = document.getElementById('val-database');

  // FAQ Accordion logic
  const faqQuestions = document.querySelectorAll('.faq-question');
  faqQuestions.forEach(btn => {
    btn.addEventListener('click', () => {
      const item = btn.closest('.faq-item');
      const isActive = item.classList.contains('active');

      // Close all other items
      document.querySelectorAll('.faq-item').forEach(el => el.classList.remove('active'));

      if (!isActive) {
        item.classList.add('active');
      }
    });
  });

  // Sample pill clicks
  sampleButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const sampleUrl = btn.getAttribute('data-url');
      input.value = sampleUrl;
      checkLink(sampleUrl);
      // Smooth scroll slightly down to show results
      input.scrollIntoView({ behavior: 'smooth', block: 'center' });
    });
  });

  // Form submit event
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const url = input.value.trim();
    if (url) {
      checkLink(url);
    }
  });

  async function checkLink(url) {
    loading.classList.remove('hidden');
    resultBox.classList.add('hidden');

    try {
      const res = await fetch('/api/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });

      if (!res.ok) {
        throw new Error(`Server status ${res.status}`);
      }

      const data = await res.json();
      renderResult(data);
    } catch (err) {
      console.warn('Backend API unavailable, executing client fallback:', err);
      const fallback = localEvaluateLink(url);
      renderResult(fallback);
    } finally {
      loading.classList.add('hidden');
    }
  }

  function renderResult(data) {
    resultUrl.textContent = data.url;

    // Badge styling & text
    resultBadge.className = 'verdict-tag';
    const status = (data.status || 'Safe').toLowerCase();
    if (status === 'fraud') {
      resultBadge.classList.add('fraud');
      resultBadge.textContent = '🚨 Malicious / Fraud';
      gaugeHint.textContent = 'High risk of credential theft or financial loss';
    } else if (status === 'suspicious') {
      resultBadge.classList.add('suspicious');
      resultBadge.textContent = '⚠️ Caution / Suspicious';
      gaugeHint.textContent = 'Unverified domain or suspicious characteristics';
    } else {
      resultBadge.classList.add('safe');
      resultBadge.textContent = '✅ Legitimate / Safe';
      gaugeHint.textContent = 'Low probability of fraudulent activity';
    }

    // Risk Score Meter
    const score = Math.min(Math.max(data.riskScore || 0, 0), 100);
    scoreText.textContent = score;
    progressBarFill.className = 'gauge-bar-fill ' + status;
    progressBarFill.style.width = `${score}%`;

    // Indicators
    const inds = data.indicators || {};
    
    // Protocol
    if (inds.protocol) {
      valProtocol.textContent = inds.protocol.value;
      indProtocol.className = 'indicator-box ' + (inds.protocol.isRisk ? 'risk' : 'clean');
    }
    // TLD
    if (inds.tld) {
      valTld.textContent = inds.tld.value;
      indTld.className = 'indicator-box ' + (inds.tld.isRisk ? 'risk' : 'clean');
    }
    // Keywords
    if (inds.keywords) {
      valKeywords.textContent = inds.keywords.value;
      indKeywords.className = 'indicator-box ' + (inds.keywords.isRisk ? 'risk' : 'clean');
    }
    // Database
    if (inds.database) {
      valDatabase.textContent = inds.database.value;
      indDatabase.className = 'indicator-box ' + (inds.database.isRisk ? 'risk' : 'clean');
    }

    // Findings List
    reasonsList.innerHTML = '';
    const reasons = data.reasons && data.reasons.length > 0
      ? data.reasons
      : ['No common phishing signatures or malicious patterns detected.'];

    reasons.forEach(reason => {
      const li = document.createElement('li');
      li.textContent = reason;
      reasonsList.appendChild(li);
    });

    resultBox.classList.remove('hidden');
  }

  // Client-Side Offline Fallback
  function localEvaluateLink(url) {
    const lower = url.trim().toLowerCase();
    const clean = lower.replace(/^https?:\/\//, '');
    const host = clean.split('/')[0].split('?')[0].split(':')[0];

    const safeList = ['google.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com', 'wikipedia.org'];
    if (safeList.some(s => host === s || host.endsWith('.' + s))) {
      return {
        url,
        status: 'Safe',
        riskScore: 5,
        indicators: {
          protocol: { value: lower.startsWith('https://') ? 'HTTPS Encrypted' : 'Standard Web', isRisk: false },
          tld: { value: '.' + host.split('.').pop(), isRisk: false },
          keywords: { value: 'Clean', isRisk: false },
          database: { value: 'Verified Safe', isRisk: false }
        },
        reasons: ['Verified legitimate domain from trusted safe list.']
      };
    }

    const fraudKeywords = ['bank', 'verify', 'login', 'kyc', 'refund', 'lottery', 'crypto', 'urgent'];
    const suspiciousTlds = ['.xyz', '.top', '.cc', '.info'];
    let riskScore = 15;
    const reasons = [];

    const isHttp = lower.startsWith('http://');
    if (isHttp) {
      riskScore += 20;
      reasons.push('Uses insecure HTTP connection.');
    }

    const matches = fraudKeywords.filter(k => lower.includes(k));
    if (matches.length > 0) {
      riskScore += 45;
      reasons.push(`Contains scam/phishing keywords: "${matches.join('", "')}".`);
    }

    const matchedTld = suspiciousTlds.find(tld => host.endsWith(tld));
    if (matchedTld) {
      riskScore += 25;
      reasons.push(`Uses a high-risk domain extension (${matchedTld}).`);
    }

    const status = riskScore >= 70 ? 'Fraud' : riskScore >= 35 ? 'Suspicious' : 'Safe';
    return {
      url,
      status,
      riskScore: Math.min(riskScore, 99),
      indicators: {
        protocol: { value: isHttp ? 'Insecure HTTP' : 'Standard Web', isRisk: isHttp },
        tld: { value: matchedTld || ('.' + host.split('.').pop()), isRisk: Boolean(matchedTld) },
        keywords: { value: matches.length > 0 ? `${matches.length} Flagged` : 'None', isRisk: matches.length > 0 },
        database: { value: status === 'Fraud' ? 'Heuristic Threat' : 'Unlisted', isRisk: status === 'Fraud' }
      },
      reasons: reasons.length > 0 ? reasons : ['No common fraud patterns detected.']
    };
  }
});
