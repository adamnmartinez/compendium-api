const express = require('express')
const cors = require('cors')
const mysql = require ('mysql2')
require('dotenv').config()
const PORT = process.env.PORT;

const app = express()

const corsOptions = {
    origin : process.env.ORIGIN, 
    methods : "GET,HEAD,PUT,PATCH,POST,DELETE",
    credentials :true,
    optionSuccessStatus : 200,
}

app.use(cors(corsOptions))
app.use(express.json())

const db = mysql.createPool({
    host: process.env.HOST,
    user: process.env.SQL_USER,
    password: process.env.SQL_PASS,
    database: process.env.SQL_DB,
    port: 3306,
    waitForConnections: true,
    connectTimeout: 60000,
    connectionLimit: 10,
    keepAliveInitialDelay: 10000,
    enableKeepAlive: true,
})

app.listen(PORT, () => {
    console.log(`Listening: http://${process.env.HOST}:${PORT}`)
    db.getConnection((err) => {
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

app.post('/register', (req, res) => {
    const { id } = req.body
    const { password } = req.body
    const sql = `INSERT INTO users (id, password) VALUES (?, ?);`
    let values = [id, password]
    db.query(sql, values, (err, data) => {
        if(err) throw err
        console.log("User registered.")
        return
    })
})

app.post('/userExists?', (req, res) => {
    const { username } = req.body
    const sql = `SELECT id FROM users WHERE username = "${username}"`
    db.query(sql, (err, data) => {
        if (data.length == 0) {
            console.log(`User with name ${username} does not exist`)
            res.json({ exists : false })
            return
        }
        console.log(`User ${username} exists`)
        res.json({ exists : true })
        return
    })
})

app.post('/initUser', (req, res) => {
    const { id } = req.body
    const { name } = req.body
    const sql = `INSERT INTO users (id, username, userlib) VALUES (?, ?, '{\"library\": []}');`
    let values = [id, name]
    db.query(sql, values, (err, data) => {
        if(err) throw err
        console.log("Initalized user library.")
        return
    })
})

app.post('/authenticate', (req, res) => {
    const { username } = req.body
    const { password } = req.body
    const id_sql = `SELECT id FROM users WHERE username = "${username}"`
    db.query(id_sql, (err, data) => {
        if (err) throw err
        if (data.length == 0){
            console.log("Could not authenticate: No such user exists")
            res.json({ valid : false })
            return
        }
        let uid = data[0].id
        const auth_sql = `SELECT password FROM registry WHERE id = "${uid}"`
        db.query(auth_sql, (_err, _data) => {
            if (_err) throw _err
            if (_data.length == 0){
                console.log("Could not authenticate: Username exists but no password registered")
                res.json({ valid : false })
                return
            }
            console.log("Authenticate: Found user")
            console.log(` - Valid Password: ${_data[0].password == password}`)
            res.json({ 
                valid : _data[0].password == password,
                id : uid
            })
            return
        })
    })
})

app.post('/:user/addBook', cors(corsOptions), (req, res) => {
    const user = req.params.user;
    const book = req.body;
    // Get the user's library
    const getSql = `SELECT userlib FROM users WHERE username = '${user}';`;
    db.query(getSql, (getErr, getData) => {
        if(getErr) throw getErr;
        let userlib = getData[0].userlib;

        // Add the new book to the library
        userlib.library.push(book);

        // Update the user's library in the database
        const updateSql = `UPDATE users SET userlib = ? WHERE username = ?;`
        let values = [JSON.stringify(userlib), user]
        db.query(updateSql, values, (updateErr, updateData) => {
            if(updateErr) {
                console.error('An error occurred:', updateErr.message);
                res.status(500).json({message: "Internal server error"});
                return;
            }
            res.json({message: "Book added successfully"});
        });
    });
});

app.post('/:user/delBook/:uuid', cors(corsOptions), (req, res) => {
    const user = req.params.user;
    const id = req.params.uuid
    // Get the user's library
    const getSql = `SELECT userlib FROM users WHERE username = '${user}';`;
    db.query(getSql, (getErr, getData) => {
        if(getErr) throw getErr;
        let userlib = getData[0].userlib;
        // Delete the new book from the library
        userlib.library.forEach(element => {
            if (element.uuid == id) {
                userlib.library.splice(userlib.library.indexOf(element), 1)
            }
        });
        // Update the user's library in the database
        const updateSql = `UPDATE users SET userlib = ? WHERE username = ?;`
        let values = [JSON.stringify(userlib), user]
        db.query(updateSql, values, (updateErr, updateData) => {
            if(updateErr) {
                console.error('An error occurred:', updateErr.message);
                res.status(500).json({message: "Internal server error"});
                return;
            }
            res.json({message: "Book deleted successfully"});
        });
    });
});

app.post('/:user/modBook/:uuid', cors(corsOptions), (req, res) => {
    const user = req.params.user;
    const id = req.params.uuid;
    const book = req.body
    // Get the user's library
    const getSql = `SELECT userlib FROM users WHERE username = '${user}';`;
    db.query(getSql, (getErr, getData) => {
        if(getErr) throw getErr;
        let userlib = getData[0].userlib;

        //Splice element with corresponding ID with new Book object
        userlib.library.forEach(element => {
            if (element.uuid == id) {
                userlib.library[userlib.library.indexOf(element)] = book
            }
        });

        // Update the user's library in the database
        const updateSql = `UPDATE users SET userlib = ? WHERE username = ?;`
        let values = [JSON.stringify(userlib), user]
        db.query(updateSql, values, (updateErr, updateData) => {
            if(updateErr) {
                console.error('An error occurred:', updateErr.message);
                res.status(500).json({message: "Internal server error"});
                return;
            }
            res.json({message: "Book modified successfully"});
        });
    });
});

app.post('/:user/addNote/:uuid', cors(corsOptions), (req, res) => {
    const user = req.params.user;
    const id = req.params.uuid;
    const note = req.body
    // Get the user's library
    const getSql = `SELECT userlib FROM users WHERE username = '${user}';`;
    db.query(getSql, (getErr, getData) => {
        if(getErr) throw getErr;
        let userlib = getData[0].userlib;

        userlib.library.forEach(element => {
            if (element.uuid == id) {
                element.notes.push(note)
            }
        });

        // Update the user's library in the database
        const updateSql = `UPDATE users SET userlib = ? WHERE username = ?;`
        let values = [JSON.stringify(userlib), user]
        db.query(updateSql, values, (updateErr, updateData) => {
            if(updateErr) {
                console.error('An error occurred:', updateErr.message);
                res.status(500).json({message: "Internal server error"});
                return;
            }
            res.json({message: "Book modified successfully"});
        });
    });
})

app.post('/:user/delNote/:book_uuid/:note_uuid', cors(corsOptions), (req, res) => {
    const user = req.params.user;
    const book_id = req.params.book_uuid;
    const note_id = req.params.note_uuid
    // Get the user's library
    const getSql = `SELECT userlib FROM users WHERE username = '${user}';`;
    db.query(getSql, (getErr, getData) => {
        if(getErr) throw getErr;
        let userlib = getData[0].userlib;

        userlib.library.forEach(element => {
            if (element.uuid == book_id) {
                element.notes.forEach(note => {
                    if (note.uuid == note_id) {
                        element.notes.splice(element.notes.indexOf(note), 1)
                    }
                })
            }
        });

        // Update the user's library in the database
        const updateSql = `UPDATE users SET userlib = ? WHERE username = ?;`
        let values = [JSON.stringify(userlib), user]
        db.query(updateSql, values, (updateErr, updateData) => {
            if(updateErr) {
                console.error('An error occurred:', updateErr.message);
                res.status(500).json({message: "Internal server error"});
                return;
            }
            res.json({message: "Book modified successfully"});
        });
    });
})

app.post('/:user/modNote/:book_uuid/:note_uuid', cors(corsOptions), (req, res) => {
    const user = req.params.user;
    const book_id = req.params.book_uuid;
    const note_id = req.params.note_uuid
    const modified = req.body
    // Get the user's library
    const getSql = `SELECT userlib FROM users WHERE username = '${user}';`;
    db.query(getSql, (getErr, getData) => {
        if(getErr) throw getErr;
        let userlib = getData[0].userlib;

        userlib.library.forEach(element => {
            if (element.uuid == book_id) {
                element.notes.forEach(note => {
                    if (note.uuid == note_id) {
                        element.notes.splice(element.notes.indexOf(note), 1, modified)
                    }
                })
            }
        });

        // Update the user's library in the database
        const updateSql = `UPDATE users SET userlib = ? WHERE username = ?;`
        let values = [JSON.stringify(userlib), user]
        db.query(updateSql, values, (updateErr, updateData) => {
            if(updateErr) {
                console.error('An error occurred:', updateErr.message);
                res.status(500).json({message: "Internal server error"});
                return;
            }
            res.json({message: "Book modified successfully"});
        });
    });
})
