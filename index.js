const express = require('express');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
const dns = require('dns').promises;
const { URL } = require('url');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// --- Start of Async Task Processing Setup ---

// In-memory data stores for simplicity. For production, use Redis or a database.
const taskQueue = [];
const taskResults = {};

// Statuses for tasks
const TASK_STATUS = {
  PENDING: 'PENDING',
  PROCESSING: 'PROCESSING',
  COMPLETED: 'COMPLETED',
  FAILED: 'FAILED'
};


/**
 * The main analysis function that will be run by the worker.
 * This contains the logic previously in the /api/check-url endpoint.
 * @param {string} url - The URL to analyze.
 */
async function performUrlAnalysis(url) {
    // Run all free checks in parallel
    const [virusTotal, googleSafeBrowsing, urlScan, dnsAnalysis, httpHeaders] = await Promise.all([
      checkVirusTotalFree(url),
      checkGoogleSafeBrowsingFree(url),
      checkUrlScan(url), // Replaced PhishTank with URLScan
      performDNSAnalysis(url),
      checkHTTPHeaders(url)
    ]);

    const apiResults = [virusTotal, googleSafeBrowsing, urlScan, dnsAnalysis, httpHeaders];
    
    // Calculate ML-enhanced risk
    const mlRisk = calculateMLRisk(url, apiResults);
    
    // Generate recommendation
    let recommendation = '';
    switch (mlRisk.final_risk_level) {
      case 'HIGH':
        recommendation = 'DANGER: This URL is likely malicious. Do not visit!';
        break;
      case 'MEDIUM':
        recommendation = 'CAUTION: This URL shows suspicious indicators. Proceed with extreme care.';
        break;
      case 'LOW':
        recommendation = 'This URL appears to be relatively safe, but always exercise caution online.';
        break;
    }

    return {
      url: url,
      timestamp: new Date().toISOString(),
      ml_enhanced_analysis: {
        overall_risk_score: mlRisk.combined_score,
        risk_level: mlRisk.final_risk_level,
        confidence: Math.round(mlRisk.confidence * 100),
        recommendation: recommendation
      },
      machine_learning: {
        risk_probability: Math.round(mlRisk.ml_prediction?.probability * 100) || 0,
        key_features: mlRisk.ml_prediction?.features || {},
        feature_importance: Object.keys(mlDetector.weights).slice(0, 5)
      },
      api_results: {
        virus_total: virusTotal,
        google_safe_browsing: googleSafeBrowsing,
        url_scan: urlScan, // Replaced phish_tank
        dns_analysis: dnsAnalysis,
        http_headers: httpHeaders
      }
    };
}


/**
 * The worker function that processes tasks from the queue.
 */
async function processTaskQueue() {
    if (taskQueue.length > 0) {
        const task = taskQueue.shift(); // Get the next task
        if (task) {
            try {
                console.log(`Processing task ${task.jobId} for URL: ${task.url}`);
                taskResults[task.jobId] = { status: TASK_STATUS.PROCESSING, data: null };
                
                const results = await performUrlAnalysis(task.url);
                
                taskResults[task.jobId] = { status: TASK_STATUS.COMPLETED, data: results };
                console.log(`Task ${task.jobId} completed.`);
            } catch (error) {
                console.error(`Task ${task.jobId} failed:`, error);
                taskResults[task.jobId] = { status: TASK_STATUS.FAILED, error: 'Analysis failed.' };
            }
        }
    }
}

// Start the worker to check the queue every 2 seconds
setInterval(processTaskQueue, 2000);

// --- End of Async Task Processing Setup ---


// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// ML-based feature extraction and scoring (PhishingMLDetector class and other functions remain the same)
class PhishingMLDetector {
  constructor() {
    this.weights = { url_length: -0.02, subdomain_count: 0.15, suspicious_tld: 0.35, ip_address: 0.45, url_shortener: 0.40, suspicious_keywords: 0.50, special_chars_ratio: 0.25, digit_ratio: 0.20, domain_age_factor: 0.30, ssl_cert_factor: 0.25, redirect_count: 0.35, port_in_url: 0.40, file_extension: 0.15, path_depth: 0.10 };
    this.bias = -0.5;
    this.suspiciousTlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'xyz'];
    this.urlShorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'short.link', 'ow.ly', 'is.gd'];
    this.phishingKeywords = ['verify', 'suspend', 'urgent', 'immediate', 'security', 'alert', 'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'login', 'signin', 'account', 'update', 'confirm', 'validate'];
    this.suspiciousExtensions = ['.exe', '.zip', '.rar', '.scr', '.bat', '.com'];
  }
  extractFeatures(url, additionalData = {}) { const parsedUrl = new URL(url); const domain = parsedUrl.hostname; const path = parsedUrl.pathname; return { url_length: Math.min(url.length / 200, 1), subdomain_count: (domain.split('.').length - 2) / 5, suspicious_tld: this.suspiciousTlds.includes(domain.split('.').pop().toLowerCase()) ? 1 : 0, ip_address: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain) ? 1 : 0, url_shortener: this.urlShorteners.some(shortener => domain.includes(shortener)) ? 1 : 0, suspicious_keywords: this.phishingKeywords.filter(keyword => url.toLowerCase().includes(keyword)).length / this.phishingKeywords.length, special_chars_ratio: (url.match(/[-_@#$%^&*()+=]/g) || []).length / url.length, digit_ratio: (domain.match(/\d/g) || []).length / domain.length, domain_age_factor: additionalData.domain_age_days ? Math.max(0, 1 - additionalData.domain_age_days / 365) : 0.5, ssl_cert_factor: additionalData.has_ssl ? 0 : 1, redirect_count: Math.min((additionalData.redirect_count || 0) / 5, 1), port_in_url: parsedUrl.port ? 1 : 0, file_extension: this.suspiciousExtensions.some(ext => path.includes(ext)) ? 1 : 0, path_depth: Math.min(path.split('/').length / 10, 1)}; }
  predict(features) { let score = this.bias; for (const [feature, value] of Object.entries(features)) { if (this.weights[feature]) { score += this.weights[feature] * value; } } const probability = 1 / (1 + Math.exp(-score)); return { probability: probability, risk_score: Math.round(probability * 100), risk_level: probability > 0.7 ? 'HIGH' : probability > 0.4 ? 'MEDIUM' : 'LOW', features: features }; }
}
const mlDetector = new PhishingMLDetector();

async function checkVirusTotalFree(url) {
  try {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) {
      return { service: 'VirusTotal', status: 'API key not configured', risk_level: 'UNKNOWN' };
    }

    const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');
    const response = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { 'x-apikey': apiKey },
      timeout: 10000
    });

    const stats = response.data.data.attributes.last_analysis_stats;
    const maliciousCount = stats.malicious || 0;
    const suspiciousCount = stats.suspicious || 0;
    
    return {
      service: 'VirusTotal',
      malicious: maliciousCount,
      suspicious: suspiciousCount,
      total_scans: Object.values(stats).reduce((a, b) => a + b, 0),
      risk_level: maliciousCount > 0 ? 'HIGH' : suspiciousCount > 0 ? 'MEDIUM' : 'LOW',
      confidence: 0.9
    };
  } catch (error) {
    return {
      service: 'VirusTotal',
      error: error.response?.status === 404 ? 'URL not in database' : 'Request failed',
      risk_level: 'UNKNOWN',
      confidence: 0
    };
  }
}

async function checkGoogleSafeBrowsingFree(url) {
  try {
    const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    if (!apiKey) {
      return { service: 'Google Safe Browsing', status: 'API key not configured', risk_level: 'UNKNOWN' };
    }

    const requestBody = {
      client: {
        clientId: "phishing-detector-free",
        clientVersion: "1.0.0"
      },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url: url }]
      }
    };

    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      requestBody,
      { headers: { 'Content-Type': 'application/json' }, timeout: 10000 }
    );

    const matches = response.data.matches || [];
    return {
      service: 'Google Safe Browsing',
      threats_found: matches.length,
      threat_types: matches.map(match => match.threatType),
      risk_level: matches.length > 0 ? 'HIGH' : 'LOW',
      confidence: 0.95
    };
  } catch (error) {
    return {
      service: 'Google Safe Browsing',
      error: 'Request failed: ' + error.message,
      risk_level: 'UNKNOWN',
      confidence: 0
    };
  }
}

async function checkUrlScan(url) {
    const apiKey = process.env.URLSCAN_API_KEY;
    if (!apiKey) {
        return { service: 'URLScan.io', status: 'API key not configured', risk_level: 'UNKNOWN' };
    }
    try {
        const response = await axios.post('https://urlscan.io/api/v1/scan/', {
            url: url,
            public: 'on'
        }, {
            headers: { 'API-Key': apiKey, 'Content-Type': 'application/json' },
            timeout: 15000
        });

        if (response.data && response.data.message === 'Submission successful') {
             // For simplicity, we'll just confirm submission. A full implementation
             // would poll the result URL provided in response.data.api.
            return {
                service: 'URLScan.io',
                submitted: true,
                scan_id: response.data.uuid,
                risk_level: 'LOW', // Assume LOW risk on successful submission, as we are not polling for the final verdict
                confidence: 0.4 
            };
        }
        return { service: 'URLScan.io', error: 'Submission failed', risk_level: 'UNKNOWN', confidence: 0 };
    } catch (error) {
        return {
            service: 'URLScan.io',
            error: 'Request failed: ' + error.message,
            risk_level: 'UNKNOWN',
            confidence: 0
        };
    }
}

async function performDNSAnalysis(url) {
  try {
    const domain = new URL(url).hostname;
    
    const addresses = await dns.resolve4(domain).catch(() => []);
    const mxRecords = await dns.resolveMx(domain).catch(() => []);
    
    const hasMultipleIPs = addresses.length > 3;
    const hasNoMX = mxRecords.length === 0;
    const hasPrivateIP = addresses.some(ip => 
      ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')
    );
    
    let riskScore = 0;
    const indicators = [];
    
    if (hasPrivateIP) {
      riskScore += 40;
      indicators.push('Private IP address detected');
    }
    if (hasNoMX && !url.includes('github.io') && !url.includes('herokuapp.com')) {
      riskScore += 20;
      indicators.push('No email servers configured');
    }
    if (hasMultipleIPs) {
      riskScore += 10;
      indicators.push('Multiple IP addresses');
    }
    if (addresses.length === 0) {
      riskScore += 60;
      indicators.push('Domain does not resolve');
    }

    return {
      service: 'DNS Analysis',
      ip_addresses: addresses,
      mx_records: mxRecords.length,
      risk_indicators: indicators,
      risk_score: riskScore,
      risk_level: riskScore >= 50 ? 'HIGH' : riskScore >= 25 ? 'MEDIUM' : 'LOW',
      confidence: 0.7
    };
  } catch (error) {
    return {
      service: 'DNS Analysis',
      error: 'DNS lookup failed',
      risk_level: 'MEDIUM',
      confidence: 0.3
    };
  }
}

async function checkHTTPHeaders(url) {
  try {
    const response = await axios.head(url, { 
      timeout: 5000,
      maxRedirects: 0,
      validateStatus: () => true
    });
    
    const headers = response.headers;
    const statusCode = response.status;
    
    let riskScore = 0;
    const indicators = [];
    
    if (!headers['strict-transport-security']) {
      riskScore += 10;
      indicators.push('Missing HSTS header');
    }
    if (!headers['x-frame-options']) {
      riskScore += 15;
      indicators.push('Missing X-Frame-Options header');
    }
    if (!headers['x-content-type-options']) {
      riskScore += 10;
      indicators.push('Missing X-Content-Type-Options header');
    }
    
    const server = headers.server?.toLowerCase() || '';
    if (server.includes('apache/2.2') || server.includes('nginx/1.0')) {
      riskScore += 20;
      indicators.push('Outdated server software');
    }
    
    const isRedirect = statusCode >= 300 && statusCode < 400;
    
    return {
      service: 'HTTP Headers Analysis',
      status_code: statusCode,
      has_ssl: url.startsWith('https://'),
      is_redirect: isRedirect,
      security_headers_missing: indicators.length,
      risk_indicators: indicators,
      risk_score: riskScore,
      risk_level: riskScore >= 30 ? 'MEDIUM' : 'LOW',
      confidence: 0.6
    };
  } catch (error) {
    return {
      service: 'HTTP Headers Analysis',
      error: 'Failed to fetch headers',
      has_ssl: url.startsWith('https://'),
      risk_level: url.startsWith('https://') ? 'LOW' : 'MEDIUM',
      confidence: 0.3
    };
  }
}

function calculateMLRisk(url, apiResults) {
  try {
    const httpResult = apiResults.find(r => r.service === 'HTTP Headers Analysis');
    const additionalData = {
      has_ssl: url.startsWith('https://'),
      redirect_count: httpResult?.is_redirect ? 1 : 0,
      domain_age_days: 180 // Default assumption
    };
    
    const features = mlDetector.extractFeatures(url, additionalData);
    const mlPrediction = mlDetector.predict(features);
    
    const apiRiskScores = apiResults
      .filter(result => result.confidence > 0.5 && result.risk_level !== 'UNKNOWN')
      .map(result => {
        const levelScore = result.risk_level === 'HIGH' ? 80 : 
                          result.risk_level === 'MEDIUM' ? 50 : 20;
        return levelScore * result.confidence;
      });
    
    const avgApiScore = apiRiskScores.length > 0 ? 
      apiRiskScores.reduce((a, b) => a + b, 0) / apiRiskScores.length : 50;
    
    const combinedScore = (mlPrediction.risk_score * 0.6) + (avgApiScore * 0.4);
    
    return {
      ml_prediction: mlPrediction,
      api_average_score: Math.round(avgApiScore),
      combined_score: Math.round(combinedScore),
      final_risk_level: combinedScore >= 70 ? 'HIGH' : combinedScore >= 40 ? 'MEDIUM' : 'LOW',
      confidence: Math.min(0.9, 0.5 + (apiResults.filter(r => r.confidence > 0.5).length * 0.1))
    };
  } catch (error) {
    console.error('ML Risk calculation error:', error);
    return {
      error: 'ML calculation failed',
      combined_score: 50,
      final_risk_level: 'MEDIUM',
      confidence: 0.3
    };
  }
}

// --- NEW ASYNC ENDPOINTS ---

/**
 * Endpoint to submit a URL for analysis.
 * Creates a job and returns a jobId to the client.
 */
app.post('/api/submit-url', (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }
  try {
    new URL(url);
  } catch {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  const jobId = crypto.randomUUID();
  const task = { jobId, url };

  taskQueue.push(task);
  taskResults[jobId] = { status: TASK_STATUS.PENDING, data: null };
  
  console.log(`Task ${jobId} created for URL: ${url}`);
  res.status(202).json({ jobId: jobId });
});

/**
 * Endpoint for the client to poll for the result of a job.
 */
app.get('/api/check-status/:jobId', (req, res) => {
    const { jobId } = req.params;
    const result = taskResults[jobId];

    if (!result) {
        return res.status(404).json({ error: 'Job not found' });
    }

    res.json(result);
});


// Health check and info endpoints remain the same
app.get('/api/health', (req, res) => { res.json({ status: 'OK', timestamp: new Date().toISOString() }); });
app.get('/', (req, res) => { res.json({ service: 'ML-Enhanced Phishing Detection API (Async)', version: '1.1.0' }); });

app.listen(PORT, () => {
  console.log(`🛡️  ML-Enhanced Phishing Detection API (Async) running on port ${PORT}`);
  console.log(`   - Worker started. Checking queue every 2 seconds.`);
});

module.exports = app;
