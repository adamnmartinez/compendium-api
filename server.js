const express = require('express')
const cors = require('cors')
const uuid = require("uuid");
const mysql = require ('mysql2')
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const { rateLimit } = require("express-rate-limit");
require('dotenv').config()
const PORT = process.env.PORT;

// bcrypt

const salt = 12;

// Rate Limiters

const register_limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 25,
  message: { error: "Too many requests", message: "Please try again later" },
  standardHeaders: "draft-8",
});

const authenticate_limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: "Too many requests", message: "Please try again later" },
  standardHeaders: "draft-8",
});

const protected_limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  message: { error: "Too many requests", message: "Please try again later" },
  standardHeaders: "draft-8",
});

// Input Validation Chains

const createUsernameChain = () =>
  body("username")
    .notEmpty()
    .withMessage("Username cannot be empty.")
    .isString()
    .withMessage("Username must be a string")
    .isLength({ min: 3, max: 50 })
    .withMessage("Username must be between 3 and 50 characters.")
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage(
      "Username can only contain letters, numbers, and underscores.",
    );

const createPasswordChain = () =>
  body("password")
    .notEmpty()
    .withMessage("Password cannot be empty.")
    .isString()
    .withMessage("Password must be a string")
    .isLength({ min: 8, max: 50 })
    .withMessage("Password must be between 8 and 50 characters.")
    .matches(/[A-Z]/)
    .withMessage("Password must contain at least one uppercase letter.")
    .matches(/[a-z]/)
    .withMessage("Password must contain at least one lowercase letter.")
    .matches(/[0-9]/)
    .withMessage("Password must contain at least one number.")
    .matches(/[!@#$%^&*]/)
    .withMessage("Password must contain at least one special character.");

const createTokenChain = () =>
  body("token")
    .notEmpty()
    .withMessage("No token provided (token is empty).")
    .isString()
    .withMessage("Provided token is not a string")
    .matches(/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/)
    .withMessage("Provided token is poorly-formatted.");



const app = express()

const corsOptions = {
    origin : process.env.ORIGIN, 
    methods : "GET,POST",
    credentials :true,
    optionSuccessStatus : 200,
}

app.use(cors(corsOptions))
app.use(helmet())
app.use(express.json())
app.use((err, req, res, next) => {
    console.error(`[ERROR] ${err.message}`);
    res.status(500).json({
      error: "Internal Server Error",
      message: "An unexpected error occurred.",
    });
  });

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
    console.log(`Listening on port ${PORT}`)
    db.getConnection((err) => {
        if(err) throw err;
        console.log('DATABASE CONNECTED');
    })
})

app.get("/", (req, res) => {
    return res.status(200).json({ message: "Server running." });
});

app.post(
    "/register",
    register_limiter,
    createUsernameChain(),
    createPasswordChain(),
    async (req, res, next) => {
        console.log(`[REGISTER] Registering new user...`);
  
        // Parse request body.
        const { username } = req.body;
        const { password } = req.body;
  
        // Get Validation Errors
        const validation = validationResult(req);
        if (!validation.isEmpty()) {
            console.log("[REGISTER] User could not be created. Bad Request.");
            return res.status(400).json({
                error: "Bad Request",
                message: `${validation.array()[0].msg}`,
            });
        }
  
        try {
            // Generate ID and Password Hash
            let id = uuid.v4();
            let hash = await bcrypt.hash(password, salt);
    
            // Construct SQL Query
            users_sql = `INSERT INTO users (id, username, hash) VALUES (?, ?, ?)`;
            let users_values = [id, username, hash];
    
            // Query Database
            db.query(users_sql, users_values, (q_err, q_res) => {
                if (q_err) {
                    console.log("SQL:")
                    console.log(q_err)
                    console.log("[REGISTER] User could not be created. Database Error.");
                    switch (q_err.errno) {
                        case 1062:
                            return res
                            .status(409)
                            .json({ error: "Conflict", message: "Username is taken." });
                        default:
                            return res.status(500).json({
                                error: "Internal Server Error",
                                message: "An unexpected error occured.",
                            });
                    }
                    
                }

                console.log(`[REGISTER] User Registered.`);

                lib_sql = `INSERT INTO userdata (id, library) VALUES (?, '{\"library\": []}')`;
                let lib_values = [id];
        
                db.query(lib_sql, lib_values, (q_err, q_res) => {
                    if (q_err) {
                        console.log(q_err)
                        console.log("[REGISTER] User Lib could not be created. Userlib Error.");
                        switch (q_err.errno) {
                            default:
                            return res.status(500).json({
                                error: "Internal Server Error",
                                message: "An unexpected error occured.",
                            });
                        }
                    }
                    console.log(`[REGISTER] New User Library Generated.`);
                    return res.status(201).json({ message: "User created." });
                })
            });
        } catch (err) {
        console.log("[REGISTER] User could not be created. Internal Error.");
        return next(err);
        }
    }
);

app.post(
    "/authenticate",
    authenticate_limiter,
    createUsernameChain(),
    createPasswordChain(),
    async (req, res, next) => {
      console.log(`[AUTH] Logging in new user`);
  
      // Parse request body.
      const { username } = req.body;
      const { password } = req.body;
  
      // Get Validation Errors
      const validation = validationResult(req);

      console.log(`[AUTH/DEBUG] Remaining requests from this IP: ${req.rateLimit.remaining}`)

      if (req.rateLimit.remaining === 0){
        return res.status(429).json({
            error: "Too Many Requests",
            message: `You have sent too many requests, please try again later.`,
          });
      }
      
      try {
        if (!validation.isEmpty()) {
          console.log("[AUTH] User could not be authenticated. Bad Request.");
          return res.status(400).json({
            error: "Bad Request",
            message: `${validation.array()[0].msg}`,
          });
        }
  
        // Construct SQL Query
        users_sql = `SELECT hash, id FROM users WHERE username = ?`;
        console.log(`[AUTH/DEBUG] Attempting to login ${username}`)
        let users_values = [username];
  
        // Query Database
        db.query(users_sql, users_values, async (q_err, q_res) => {
            if (q_err) {
                console.log(
                "[AUTH] User could not be authenticated. Database Error.",
                );
                switch (q_err.errno) {
                default:
                    res.status(500).json({
                    error: "Internal Server Error",
                    message: "An unexpected error occured.",
                    });
                    break;
                }
                return;
            }  
            
            if (q_res.length == 0) {
                console.log("[AUTH] No such user found");
                return res.status(401).json({
                error: "Unauthorized",
                message: "Username or password is incorrect.",
                });
            } 

            console.log(`[AUTH] Credentials verified.`);
            const user = q_res[0]
            const passwordCompare = await bcrypt.compare(password, user.hash)
            if (passwordCompare) {
              console.log(`[AUTH/DEBUG] Creating token for user ${username}(${user.id})`)
              let token = jwt.sign(
                { 
                    id: user.id,
                    user: username
                },
                process.env.SECRET_KEY,
                { expiresIn: `${process.env.AUTH_EXPIRE}` },
              );
              return res
                .status(200)
                .json({ message: "User authenticated.", token: `${token}` });
            } else {
              console.log(`[AUTH] Could not verify credentials.`);
              return res.status(401).json({
                error: "Unauthorized",
                message: "Username or password is incorrect.",
              });
            }
        });
      } catch (err) {
        console.log("[AUTH] User could not be authenticated. Internal Error.");
        return next(err);
      }
    },
);

//app.post("/account", protected_limiter, createTokenChain(), (req, res) => {
app.post("/account", createTokenChain(), (req, res) => {
    const { token } = req.body;

    const validation = validationResult(req);
  
    if (!validation.isEmpty()) {
      console.log("[PROTECTED] User cannot access resource, bad token.");
      return res.status(400).json({
        error: "Bad Request",
        message: `${validation.array()[0].msg}`,
      });
    }
  
    jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
      if (err) {
        if (err.name === "TokenExpiredError") {
          return res.status(403).json({
            error: "Unauthorized",
            message:
              "Could not authorize user, expired token. Please log in again.",
          });
        } else if (err.name === "JsonWebTokenError") {
          return res.status(403).json({
            error: "Unauthorized",
            message:
              "Could not authorize user, invalid token. Please log in again.",
          });
        } else {
          return res.status(500).json({
            error: "Internal Server Error",
            message: "An unexpected error occured.",
          });
        }
      }

      try {
        lib_sql = `SELECT library FROM userdata WHERE id = ?`;
        lib_values = [decoded.id]
        console.log("[PROTECTED/DEBUG] Decrypted payload")
        console.log(decoded)

        db.query(lib_sql, lib_values, (q_err, q_res) => {
            if (q_err) {
                console.log(
                  "[PROTECTED] User could not be authenticated. Database Error.",
                );
                switch (q_err.errno) {
                  default:
                    res.status(500).json({
                      error: "Internal Server Error",
                      message: "An unexpected error occured.",
                    });
                    break;
                }
                return;
            } else if (q_res.length == 0) {
                console.log("[PROTECTED] No such user found");
                return res.status(404).json({
                  error: "Not Found",
                  message: "Could Not Find User's Library.",
                });
            } else {
                userdata = q_res[0]
                return res
                .status(200)
                .json({ message: `User identity verified. Loading Library...`, library: userdata.library, user: decoded.user, id: decoded.id });
            }
        })
      } catch {
        return res.status(500).json({
            error: "Internal Server Error",
            message: "An unexpected error occured.",
          });
      }
    });
});


app.post('/:user/addBook', (req, res) => {
    const user = req.params.user;
    const book = req.body;
    // Get the user's library
    const getSql = `SELECT library FROM users WHERE username = '${user}';`;
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

app.post('/:user/delBook/:uuid', (req, res) => {
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

app.post('/:user/modBook/:uuid', (req, res) => {
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

app.post('/:user/addNote/:uuid', (req, res) => {
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

app.post('/:user/delNote/:book_uuid/:note_uuid', (req, res) => {
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

app.post('/:user/modNote/:book_uuid/:note_uuid', (req, res) => {
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
