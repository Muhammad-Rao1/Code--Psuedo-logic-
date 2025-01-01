const express = require('express');
const axios = require('axios');
const base64 = require('base-64');
const crypto = require('crypto');
const qs = require('qs');
require('dotenv').config();

const router = express.Router();

const { ZOHO_AUTH_URL, REDIRECT_URI, ZOHO_TOKEN_URL, QBO_TOKEN_URL, DOCUSIGN_TOKEN_URL } = process.env;

// Store for authorization code and state
let authorizationData = {};
let stateStore = {}; // Store state values per session
let pkceStore = {}; // Store PKCE values (codeVerifier and codeChallenge)

// Helper function for Base64 encoding
const encodeClientCredentials = (client_id, client_secret) => {
    const credentials = `${client_id}:${client_secret}`;
    return base64.encode(credentials);
};

// Generate a random string
const generateRandomString = (length) => crypto.randomBytes(length).toString('hex');

// Generate code challenge for PKCE
const generateCodeChallenge = (codeVerifier) => {
    return crypto
        .createHash('sha256')
        .update(codeVerifier)
        .digest('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
};

// Step 1: Generate Authorization URL
router.post('/authorize', (req, res) => {
    const { client_id, redirect_uri, scope, service } = req.body;

    if (!client_id || !redirect_uri || !scope || !service) {
        return res.status(400).json({ error: 'Missing required fields.' });
    }

    const state = generateRandomString(16);
    const codeVerifier = generateRandomString(32);
    const codeChallenge = generateCodeChallenge(codeVerifier);

    // Store state and PKCE values
    stateStore[state] = service;
    pkceStore[state] = { codeVerifier, codeChallenge };

    let authUrl;
    if (service === 'zoho') {
        authUrl = `${ZOHO_AUTH_URL}?response_type=code&client_id=${client_id}&redirect_uri=${REDIRECT_URI}&scope=${scope}&access_type=offline`;
    } else if (service === 'quickbooks') {
        authUrl = `https://appcenter.intuit.com/connect/oauth2?client_id=${client_id}&response_type=code&scope=${scope}&redirect_uri=${REDIRECT_URI}&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256`;
    } else if (service === 'docusign') {
        authUrl = `https://account.docusign.com/oauth/auth?client_id=${client_id}&response_type=code&redirect_uri=${REDIRECT_URI}&scope=${scope}&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256`;
    } else {
        return res.status(400).json({ error: 'Unsupported service.' });
    }

    res.json({ authorization_url: authUrl });
});

// Step 2: Receive Authorization Code
router.get('/callback', (req, res) => {
    const { code, state } = req.query;

    if (!code || !state) {
        return res.status(400).send('Authorization code or state is missing.');
    }

    // Validate state
    if (!stateStore[state]) {
        return res.status(400).send('Invalid or missing state.');
    }

    authorizationData = { code };
    res.status(200).json({ message: 'Authorization code received.', authorizationData });
});

// Step 3: Exchange Authorization Code for Tokens
router.post('/get-tokens', async (req, res) => {
    const { client_id, client_secret, redirect_uri, service } = req.body;

    if (!authorizationData.code || !client_id || !client_secret || !redirect_uri || !service) {
        return res.status(400).json({ error: 'Missing required fields or authorization code.' });
    }

    try {
        let tokenResponse;
        const codeVerifier = pkceStore[stateStore[service]]?.codeVerifier;

        if (service === 'zoho') {
            tokenResponse = await axios.post(ZOHO_TOKEN_URL, null, {
                params: {
                    grant_type: 'authorization_code',
                    client_id,
                    client_secret,
                    redirect_uri,
                    code: authorizationData.code,
                },
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            });
        } else if (service === 'quickbooks') {
            const authHeader = `Basic ${encodeClientCredentials(client_id, client_secret)}`;
            tokenResponse = await axios.post(QBO_TOKEN_URL, qs.stringify({
                grant_type: 'authorization_code',
                code: authorizationData.code,
                redirect_uri,
                code_verifier: codeVerifier,
            }), {
                headers: { 'Authorization': authHeader, 'Content-Type': 'application/x-www-form-urlencoded' }
            });
        } else if (service === 'docusign') {
            const authHeader = `Basic ${encodeClientCredentials(client_id, client_secret)}`;
            tokenResponse = await axios.post(DOCUSIGN_TOKEN_URL, qs.stringify({
                grant_type: 'authorization_code',
                code: authorizationData.code,
                redirect_uri,
                code_verifier: codeVerifier,
            }), {
                headers: { 'Authorization': authHeader, 'Content-Type': 'application/x-www-form-urlencoded' }
            });
        } else {
            return res.status(400).json({ error: 'Unsupported service.' });
        }

        const { access_token, refresh_token, expires_in, token_type } = tokenResponse.data;
        res.json({ access_token, refresh_token, token_type, expires_in });
    } catch (error) {
        res.status(500).json({ error: 'Error retrieving tokens.' });
    }
});

module.exports = router;
