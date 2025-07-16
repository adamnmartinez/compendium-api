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
    .matches(/[!@#$%^&*_]/)
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

                // lib_sql = `INSERT INTO userdata (id, library) VALUES (?, '{\"library\": []}')`;

                lib_sql = `INSERT INTO userdata (id, library) VALUES (?, '[]')`;

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

      // console.log(`[AUTH/DEBUG] Remaining requests from this IP: ${req.rateLimit.remaining}`)

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
        // console.log(`[AUTH/DEBUG] Attempting to login ${username}`)
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
              // console.log(`[AUTH/DEBUG] Creating token for user ${username}(${user.id})`)
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

        db.query(lib_sql, lib_values, (q_err, q_res) => {
            if (q_err) {
                console.log(
                  "[PROTECTED] User could not be authenticated. Database Query Error",
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

app.post("/account/library/add", createTokenChain(), (req, res) => {
    const { token } = req.body;
    const { book } = req.body;

    const validation = validationResult(req);
  
    if (!validation.isEmpty()) {
      console.log("[LIBRARY/ADD] User cannot access resource, bad token.");
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
        // console.log("[LIBRARY/ADD/DEBUG] Decrypted payload")
        // console.log(decoded)

        db.query(lib_sql, lib_values, (q_err, q_res) => {
            if (q_err) {
                console.log(
                  "[LIBRARY/ADD] User could not be authenticated. Database Error.",
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
                console.log("[LIBRARY/ADD] No such user found");
                return res.status(404).json({
                  error: "Not Found",
                  message: "Could Not Find User's Library.",
                });
            } else {
                // console.log("[LIBRARY/ADD] Found user library, adding book...")
                // console.log("[LIBRARY/ADD/DEBUG] Reading user library: ")

                newlibrary = q_res[0].library

                newlibrary.push(book)

                add_sql = `UPDATE userdata SET library = ? WHERE id = ?`
                add_values = [JSON.stringify(newlibrary), decoded.id]

                db.query(add_sql, add_values, (r_err, r_res) => {
                    if (r_err) {
                        console.log(
                          "[LIBRARY/ADD] User could not be authenticated. Database Error.",
                        );
                        switch (r_err.errno) {
                          default:
                            res.status(500).json({
                              error: "Internal Server Error",
                              message: "An unexpected error occured.",
                            });
                            break;
                        }
                        return;
                    } else if (r_res.length == 0) {
                        console.log("[LIBRARY/ADD] Couldn't find a library to update.");
                        return res.status(404).json({
                          error: "Not Found",
                          message: "Could Not Find User's Library.",
                        });
                    } else {
                        console.log("[LIBRARY/ADD] Library updated successfully.")
                        return res
                        .status(200)
                        .json({ message: `User identity verified, library updated.`, library: newlibrary, user: decoded.user, id: decoded.id });
                    }
                }) 
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

app.post("/account/library/remove", createTokenChain(), (req, res) => {
    const { token } = req.body;
    const { uuid } = req.body;

    const validation = validationResult(req);
  
    if (!validation.isEmpty()) {
      console.log("[LIBRARY/REMOVE] User cannot access resource, bad token.");
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
        // console.log("[LIBRARY/REMOVE/DEBUG] Decrypted payload")
        // console.log(decoded)

        db.query(lib_sql, lib_values, (q_err, q_res) => {
            if (q_err) {
                console.log(
                  "[LIBRARY/REMOVE] User could not be authenticated. Database Error.",
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
                console.log("[LIBRARY/REMOVE] No such user found");
                return res.status(404).json({
                  error: "Not Found",
                  message: "Could Not Find User's Library.",
                });
            } else {
                console.log("[LIBRARY/REMOVE] Found user library, searching for book...")
                // console.log("[LIBRARY/REMOVE/DEBUG] Reading user library: ")
                // console.log(q_res[0].library)

                newlibrary = q_res[0].library

                removeIndex = -1

                for (let i = 0; i < newlibrary.length; i++) {
                    entry = newlibrary[i]
                    if (entry.uuid == uuid) {
                        removeIndex = i
                        break;
                    }
                }

                if (removeIndex < 0) {
                    console.log("[LIBRARY/REMOVE] Couldn't find the requested book to delete.")
                    return res
                    .status(404)
                    .json({ message: `Could not find the requested book.`, library: newlibrary, user: decoded.user, id: decoded.id });
                } else {
                    newlibrary.splice(removeIndex, 1)
                }

                add_sql = `UPDATE userdata SET library = ? WHERE id = ?`
                add_values = [JSON.stringify(newlibrary), decoded.id]

                db.query(add_sql, add_values, (r_err, r_res) => {
                    if (r_err) {
                        console.log(
                          "[LIBRARY/REMOVE] User could not be authenticated. Database Error.",
                        );
                        switch (r_err.errno) {
                          default:
                            res.status(500).json({
                              error: "Internal Server Error",
                              message: "An unexpected error occured.",
                            });
                            break;
                        }
                        return;
                    } else if (r_res.length == 0) {
                        console.log("[LIBRARY/REMOVE] Couldn't find a library to update.");
                        return res.status(404).json({
                          error: "Not Found",
                          message: "Could Not Find User's Library.",
                        });
                    } else {
                        console.log("[LIBRARY/REMOVE] Library updated successfully.")
                        return res
                        .status(200)
                        .json({ message: `User identity verified, library updated.`, library: newlibrary, user: decoded.user, id: decoded.id });
                    }
                }) 
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

app.post("/account/library/edit", createTokenChain(), (req, res) => {
    const { token } = req.body;
    const { modified } = req.body;
    const { uuid } = req.body;

    const validation = validationResult(req);
  
    if (!validation.isEmpty()) {
      console.log("[LIBRARY/EDIT] User cannot access resource, bad token.");
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

        db.query(lib_sql, lib_values, (q_err, q_res) => {
            if (q_err) {
                console.log(
                  "[LIBRARY/EDIT] User could not be authenticated. Database Error.",
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
                console.log("[LIBRARY/EDIT] No such user found");
                return res.status(404).json({
                  error: "Not Found",
                  message: "Could Not Find User's Library.",
                });
            } else {
                newlibrary = q_res[0].library
                editIndex = -1

                for (let i = 0; i < newlibrary.length; i++) {
                    entry = newlibrary[i]
                    if (entry.uuid == uuid) {
                        editIndex = i
                        break;
                    }
                }

                if (editIndex < 0) {
                    console.log("[LIBRARY/EDIT] Couldn't find the requested book to modify.")
                    return res
                    .status(404)
                    .json({ message: `Could not find the requested book.`, library: newlibrary, user: decoded.user, id: decoded.id });
                }
                
                //newlibrary.splice(removeIndex, 1)

                newlibrary[editIndex] = modified

                add_sql = `UPDATE userdata SET library = ? WHERE id = ?`
                add_values = [JSON.stringify(newlibrary), decoded.id]

                db.query(add_sql, add_values, (r_err, r_res) => {
                    if (r_err) {
                        console.log(
                          "[LIBRARY/EDIT] User could not be authenticated. Database Error.",
                        );
                        switch (r_err.errno) {
                          default:
                            res.status(500).json({
                              error: "Internal Server Error",
                              message: "An unexpected error occured.",
                            });
                            break;
                        }
                        return;
                    } else if (r_res.length == 0) {
                        console.log("[LIBRARY/EDIT] Couldn't find a library to update.");
                        return res.status(404).json({
                          error: "Not Found",
                          message: "Could Not Find User's Library.",
                        });
                    } else {
                        console.log("[LIBRARY/EDIT] Library updated successfully.")
                        return res
                        .status(200)
                        .json({ message: `User identity verified, library updated.`, library: newlibrary, user: decoded.user, id: decoded.id });
                    }
                }) 
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

app.post("/account/library/entry/add", createTokenChain(), (req, res) => {
    const { token } = req.body;
    const { bookID } = req.body;
    const { note } = req.body;

    const validation = validationResult(req);
  
    if (!validation.isEmpty()) {
      console.log("[LIBRARY/ENTRY/ADD] User cannot access resource, bad token.");
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

        db.query(lib_sql, lib_values, (q_err, q_res) => {
            if (q_err) {
                console.log(
                  "[LIBRARY/ENTRY/ADD] User could not be authenticated. Database Error.",
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
                console.log("[LIBRARY/ENTRY/ADD] No such user found");
                return res.status(404).json({
                  error: "Not Found",
                  message: "Could Not Find User's Library.",
                });
            } else {
                let newlibrary = q_res[0].library
                let editIndex = -1

                for (let i = 0; i < newlibrary.length; i++) {
                    if (newlibrary[i].uuid == bookID) {
                        editIndex = i
                        break
                    }
                }

                if (editIndex < 0) {
                    return res.status(404).json({
                        error: "Not Found",
                        message: "Could Not Find User's Library.",
                    });
                }

                newlibrary[editIndex].notes.push(note)
 
                add_sql = `UPDATE userdata SET library = ? WHERE id = ?`
                add_values = [JSON.stringify(newlibrary), decoded.id]

                db.query(add_sql, add_values, (r_err, r_res) => {
                    if (r_err) {
                        console.log(
                          "[LIBRARY/ENTRY/ADD] User could not be authenticated. Database Error.",
                        );
                        switch (r_err.errno) {
                          default:
                            res.status(500).json({
                              error: "Internal Server Error",
                              message: "An unexpected error occured.",
                            });
                            break;
                        }
                        return;
                    } else if (r_res.length == 0) {
                        console.log("[LIBRARY/ENTRY/ADD] Couldn't find a library to update.");
                        return res.status(404).json({
                          error: "Not Found",
                          message: "Could Not Find User's Library.",
                        });
                    } else {
                        console.log("[LIBRARY/ENTRY/ADD] Library updated successfully.")
                        return res
                        .status(200)
                        .json({ message: `User identity verified, library updated.`, library: newlibrary, user: decoded.user, id: decoded.id });
                    }
                }) 
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

app.post("/account/library/entry/remove", createTokenChain(), (req, res) => {
    const { token } = req.body;
    const { bookID } = req.body;
    const { noteID } = req.body;

    const validation = validationResult(req);
  
    if (!validation.isEmpty()) {
      console.log("[LIBRARY/ENTRY/ADD] User cannot access resource, bad token.");
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

        db.query(lib_sql, lib_values, (q_err, q_res) => {
            if (q_err) {
                console.log(
                  "[LIBRARY/ENTRY/ADD] User could not be authenticated. Database Error.",
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
                console.log("[LIBRARY/ENTRY/ADD] No such user found");
                return res.status(404).json({
                  error: "Not Found",
                  message: "Could Not Find User's Library.",
                });
            } else {
                let newlibrary = q_res[0].library
                let editIndex = -1
                let removeIndex = -1

                for (let i = 0; i < newlibrary.length; i++) {
                    if (newlibrary[i].uuid == bookID) {
                        editIndex = i
                        break
                    }
                }

                if (editIndex < 0) {
                    return res.status(404).json({
                        error: "Not Found",
                        message: "Could Not Find Book.",
                    });
                }

                //console.log(newlibrary[editIndex].notes)
                //console.log(noteID)

                for (let i = 0; i < newlibrary[editIndex].notes.length; i++) {
                    if (newlibrary[editIndex].notes[i].uuid == noteID) {
                        removeIndex = i
                        break;
                    }
                }

                if (removeIndex < 0) {
                    return res.status(404).json({
                        error: "Not Found",
                        message: "Could Not Find Note.",
                    });
                }

                newlibrary[editIndex].notes.splice(removeIndex, 1)
 
                add_sql = `UPDATE userdata SET library = ? WHERE id = ?`
                add_values = [JSON.stringify(newlibrary), decoded.id]

                db.query(add_sql, add_values, (r_err, r_res) => {
                    if (r_err) {
                        console.log(
                          "[LIBRARY/ENTRY/ADD] User could not be authenticated. Database Error.",
                        );
                        switch (r_err.errno) {
                          default:
                            res.status(500).json({
                              error: "Internal Server Error",
                              message: "An unexpected error occured.",
                            });
                            break;
                        }
                        return;
                    } else if (r_res.length == 0) {
                        console.log("[LIBRARY/ENTRY/ADD] Couldn't find a library to update.");
                        return res.status(404).json({
                          error: "Not Found",
                          message: "Could Not Find User's Library.",
                        });
                    } else {
                        console.log("[LIBRARY/ENTRY/ADD] Library updated successfully.")
                        return res
                        .status(200)
                        .json({ message: `User identity verified, library updated.`, library: newlibrary, user: decoded.user, id: decoded.id });
                    }
                }) 
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

app.post("/account/library/entry/edit", createTokenChain(), (req, res) => {
    const { token } = req.body;
    const { bookID } = req.body;
    const { noteID } = req.body
    const { modified } = req.body;

    const validation = validationResult(req);
  
    if (!validation.isEmpty()) {
      console.log("[LIBRARY/ENTRY/ADD] User cannot access resource, bad token.");
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

        db.query(lib_sql, lib_values, (q_err, q_res) => {
            if (q_err) {
                console.log(
                  "[LIBRARY/ENTRY/ADD] User could not be authenticated. Database Error.",
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
                console.log("[LIBRARY/ENTRY/ADD] No such user found");
                return res.status(404).json({
                  error: "Not Found",
                  message: "Could Not Find User's Library.",
                });
            } else {
                let newlibrary = q_res[0].library
                let editIndex = -1
                let noteIndex = -1

                for (let i = 0; i < newlibrary.length; i++) {
                    if (newlibrary[i].uuid == bookID) {
                        editIndex = i
                        break
                    }
                }

                if (editIndex < 0) {
                    return res.status(404).json({
                        error: "Not Found",
                        message: "Could Not Find Book.",
                    });
                }


                for (let i = 0; i < newlibrary[editIndex].notes.length; i++) {
                    if (newlibrary[editIndex].notes[i].uuid == noteID) {
                        noteIndex = i
                        break;
                    }
                }
                
                if (noteIndex < 0) {
                    return res.status(404).json({
                        error: "Not Found",
                        message: "Could Not Find Note.",
                    });
                }

                newlibrary[editIndex].notes[noteIndex] = modified
 
                add_sql = `UPDATE userdata SET library = ? WHERE id = ?`
                add_values = [JSON.stringify(newlibrary), decoded.id]

                db.query(add_sql, add_values, (r_err, r_res) => {
                    if (r_err) {
                        console.log(
                          "[LIBRARY/ENTRY/ADD] User could not be authenticated. Database Error.",
                        );
                        switch (r_err.errno) {
                          default:
                            res.status(500).json({
                              error: "Internal Server Error",
                              message: "An unexpected error occured.",
                            });
                            break;
                        }
                        return;
                    } else if (r_res.length == 0) {
                        console.log("[LIBRARY/ENTRY/ADD] Couldn't find a library to update.");
                        return res.status(404).json({
                          error: "Not Found",
                          message: "Could Not Find User's Library.",
                        });
                    } else {
                        console.log("[LIBRARY/ENTRY/ADD] Library updated successfully.")
                        return res
                        .status(200)
                        .json({ message: `User identity verified, library updated.`, library: newlibrary, user: decoded.user, id: decoded.id });
                    }
                }) 
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
