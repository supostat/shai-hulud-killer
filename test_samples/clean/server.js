// Clean JavaScript file - should NOT trigger any alerts
// This is a normal, legitimate file for testing false positives

const express = require('express');
const app = express();

app.get('/', (req, res) => {
    res.send('Hello World!');
});

app.get('/api/users', async (req, res) => {
    const users = await getUsers();
    res.json(users);
});

async function getUsers() {
    return [
        { id: 1, name: 'Alice' },
        { id: 2, name: 'Bob' },
    ];
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;
