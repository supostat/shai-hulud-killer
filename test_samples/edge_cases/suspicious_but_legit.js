// Edge case: File with some suspicious-looking but legitimate patterns
// Should trigger MEDIUM severity at most, not CRITICAL

const config = {
    // This is a legitimate use of environment variables
    githubToken: process.env.GITHUB_TOKEN,  // Medium: env var reference
    
    // Legitimate npm config path reference in documentation
    // Users should check their .npmrc for authentication
    configPath: '~/.npmrc',  // Medium: npmrc reference
};

// Legitimate use of eval for JSON parsing fallback (still flagged but not critical)
function parseConfig(str) {
    try {
        return JSON.parse(str);
    } catch (e) {
        // This is bad practice but not malware
        // eval(str);  -- commented out, should not trigger
        return null;
    }
}

// Legitimate GitHub Actions self-hosted runner documentation
const docs = `
# Setting up self-hosted runners
# 
# You can use self-hosted runners for private CI/CD.
# See: https://docs.github.com/en/actions/hosting-your-own-runners
`;

module.exports = { config, parseConfig };
