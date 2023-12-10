const express = require('express')
const cors = require('cors')
const mysql = require ('mysql2')
require('dotenv').config()
const PORT = process.env.PORT;

const app = express()

const corsOptions = {
    origin :'*', 
    methods : "GET,HEAD,PUT,PATCH,POST,DELETE",
    credentials :true,
    optionSuccessStatus : 200,
}

app.use(cors(corsOptions))
app.use(express.json())

const db = mysql.createConnection({
    host: process.env.HOST,
    user: process.env.SQL_USER,
    password: process.env.SQL_PASS,
    database: process.env.SQL_DB,
    port: 3307
})

app.listen(PORT, () => {
    console.log(`Listening: https://${process.env.HOST}:${PORT}`)
    db.connect((err) => {
        if(err) throw err;
        console.log('DATABASE CONNECTED');
    })
})

app.get('/', cors(corsOptions), (req, res) => {
    return res.json('Backend');
})

app.get('/users', cors(corsOptions), (req, res) => {
    const sql = "SELECT * FROM users;"
    db.query(sql, (err, data) => {
        if(err) throw err;
        return res.json(data)
    })
})

app.post('/register', cors(corsOptions), (req, res) => {
    const { name } = req.body
    const { pass } = req.body
    const sql = `INSERT INTO users (username, userpass, userlib) VALUES ('${name}', '${pass}', '{\"library\": []}');`
    db.query(sql, (err, data) => {
        if(err) throw err;
        return
    })
})

app.post('/:user/setlib', cors(corsOptions), (req, res) => {
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

app.route('/:user/addBook', cors(corsOptions), (req, res) => {
    const user = req.params.user
    const { book } = req.body
    const userlib = null
    .get((req, res) => {
        const sql = `SELECT '${user}' FROM users;`
        db.query(sql, (err, data) => {
            if(err) throw err;
            userlib = res.json(data).library
        })
    })
    userlib.push(book)
    .post((req, res) => {
        const sql =  `UPDATE users SET userlib = '${userlib}' WHERE username = '${user}'`
        db.query(sql, (err, data) => {
            if(err) throw err;
            return
        })
    })
})

// app.route('/:user/delBook/:bookname', cors(corsOptions), (req, res) => {
//     const user = req.params.user
//     const book = req.params.bookname
//     const userlib = null
//     .get((req, res) => {
//         const sql = `SELECT '${user}' FROM users;`
//         db.query(sql, (err, data) => {
//             if(err) throw err;
//             userlib = res.json(data).library
//         })
//     })
//     .post((req, res) => {
//         const sql =  `UPDATE users SET userlib = '${userlib}' WHERE username = '${user}'`
//         db.query(sql, (err, data) => {
//             if(err) throw err;
//             return
//         })
//     })
// })