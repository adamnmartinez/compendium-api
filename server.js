const express = require('express')
const cors = require('cors')
const mysql = require ('mysql2')
require('dotenv').config()
const PORT = 8080;

const app = express()
app.use(cors())
app.use(express.json())

const db = mysql.createConnection({
    host: process.env.HOST,
    user: process.env.SQL_USER,
    password: process.env.SQL_PASS,
    database: process.env.SQL_DB,
})

app.listen(PORT, () => {
    console.log(`Listening: https://${process.env.HOST}:${PORT}`)
    db.connect((err) => {
        if(err) throw err;
        console.log('DATABASE CONNECTED');
    })
})

app.get('/', (req, res) => {
    return res.json('Backend');
})

app.get('/users', (req, res) => {
    const sql = "SELECT * FROM users;"
    db.query(sql, (err, data) => {
        if(err) throw err;
        return res.json(data)
    })
})

app.post('/register', (req, res) => {
    const { name } = req.body
    const { pass } = req.body
    const sql = `INSERT INTO users (username, userpass, userlib) VALUES ('${name}', '${pass}', '{\"library\": []}');`
    db.query(sql, (err, data) => {
        if(err) throw err;
        return
    })
})

app.post('/:user/setlib', (req, res) => {
    const { user } = req.params
    const { bodylib } = req.body
    const newlib = JSON.stringify({ "library": bodylib })
    console.log(newlib)
    const sql =  `UPDATE users SET userlib = '${newlib}' WHERE username = '${user}'`
    db.query(sql, (err, data) => {
        if(err) throw err;
        return
    })
})