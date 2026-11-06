const crypto = require('node:crypto');
const Busboy = require('busboy');

const OWNER = 'raziel47';
const REPO = 'raziel47';
const BRANCH = 'main';
const LOGO_PATH = 'assets/signature-logo.png';
const MAX_FILE_SIZE = 5 * 1024 * 1024;
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function send(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(body));
}

function applyCors(req, res) {
  const allowedOrigin = process.env.APP_ORIGIN;
  const origin = req.headers.origin;
  if (!allowedOrigin) return false;
  if (origin && origin === allowedOrigin.replace(/\/$/, '')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
  return !origin || origin === allowedOrigin.replace(/\/$/, '');
}

function makeAppJWT() {
  const appId = process.env.GITHUB_APP_ID;
  const privateKey = (process.env.GITHUB_APP_PRIVATE_KEY || '').replace(/\\n/g, '\n');
  if (!appId || !privateKey || !process.env.GITHUB_INSTALLATION_ID) {
    throw new Error('GitHub App environment is not configured');
  }
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const unsigned = `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode({ iat: now - 60, exp: now + 540, iss: appId })}`;
  const signature = crypto.sign('RSA-SHA256', Buffer.from(unsigned), privateKey).toString('base64url');
  return `${unsigned}.${signature}`;
}

async function getInstallationToken() {
  const jwt = makeAppJWT();
  const response = await fetch(`https://api.github.com/app/installations/${encodeURIComponent(process.env.GITHUB_INSTALLATION_ID)}/access_tokens`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${jwt}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' }
  });
  if (!response.ok) throw new Error(`GitHub App token request failed (${response.status})`);
  const result = await response.json();
  if (!result.token) throw new Error('GitHub did not return an installation token');
  return result.token;
}

async function githubRequest(token, method, path, body) {
  return fetch(`https://api.github.com${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(body ? { 'Content-Type': 'application/json' } : {})
    },
    ...(body ? { body: JSON.stringify(body) } : {})
  });
}

function readPngUpload(req) {
  return new Promise((resolve, reject) => {
    let parser;
    try {
      parser = Busboy({ headers: req.headers, limits: { fileSize: MAX_FILE_SIZE, files: 1, fields: 0, parts: 1 } });
    } catch (_) {
      reject(new Error('Send a multipart form with one PNG file.'));
      return;
    }
    let fileBuffer = null;
    let fileSeen = false;
    let invalidType = false;
    let tooLarge = false;
    let settled = false;
    const fail = error => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    parser.on('file', (fieldName, stream, info) => {
      fileSeen = true;
      if (fieldName !== 'logo' || info.mimeType !== 'image/png') invalidType = true;
      const chunks = [];
      stream.on('limit', () => { tooLarge = true; });
      stream.on('data', chunk => chunks.push(chunk));
      stream.on('end', () => { fileBuffer = Buffer.concat(chunks); });
    });
    parser.on('filesLimit', () => { tooLarge = true; });
    parser.on('fieldsLimit', () => { invalidType = true; });
    parser.on('error', () => fail(new Error('Could not read the uploaded file.')));
    parser.on('finish', () => {
      if (settled) return;
      if (tooLarge) return fail(new Error('The image must be 5 MB or smaller.'));
      if (invalidType || !fileSeen || !fileBuffer) return fail(new Error('Upload one PNG image using the logo field.'));
      if (fileBuffer.length < PNG_SIGNATURE.length || !fileBuffer.subarray(0, PNG_SIGNATURE.length).equals(PNG_SIGNATURE)) {
        return fail(new Error('The uploaded file is not a valid PNG image.'));
      }
      settled = true;
      resolve(fileBuffer);
    });
    req.pipe(parser);
  });
}

module.exports = async function handler(req, res) {
  if (!applyCors(req, res)) return send(res, 403, { error: 'Request origin is not allowed.' });
  if (req.method === 'OPTIONS') { res.statusCode = 204; return res.end(); }
  if (req.method !== 'GET' && req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST, OPTIONS');
    return send(res, 405, { error: 'Method not allowed.' });
  }

  try {
    const token = await getInstallationToken();
    const contentsPath = `/repos/${OWNER}/${REPO}/contents/${LOGO_PATH}?ref=${BRANCH}`;
    if (req.method === 'GET') {
      const response = await githubRequest(token, 'GET', contentsPath);
      if (response.status === 404) return send(res, 200, { exists: false });
      if (!response.ok) throw new Error(`GitHub logo lookup failed (${response.status})`);
      return send(res, 200, { exists: true });
    }

    const content = await readPngUpload(req);
    const currentResponse = await githubRequest(token, 'GET', contentsPath);
    let sha;
    if (currentResponse.ok) sha = (await currentResponse.json()).sha;
    else if (currentResponse.status !== 404) throw new Error(`GitHub logo lookup failed (${currentResponse.status})`);

    const commitBody = {
      message: 'Update email signature logo',
      content: content.toString('base64'),
      branch: BRANCH,
      ...(sha ? { sha } : {})
    };
    const commitResponse = await githubRequest(token, 'PUT', `/repos/${OWNER}/${REPO}/contents/${LOGO_PATH}`, commitBody);
    if (!commitResponse.ok) throw new Error(`GitHub could not commit the logo (${commitResponse.status})`);
    const result = await commitResponse.json();
    return send(res, 200, { commitSha: result.commit.sha, commitUrl: result.commit.html_url });
  } catch (error) {
    console.error('Signature logo API error:', error.message);
    const message = error.message.includes('environment is not configured')
      ? 'The secure GitHub App backend is not configured yet.'
      : error.message.startsWith('The image') || error.message.startsWith('Upload one') || error.message.startsWith('Send a multipart') || error.message.startsWith('Could not read')
        ? error.message
        : 'Upload could not be completed. Check the Vercel and GitHub App configuration.';
    return send(res, 500, { error: message });
  }
};
