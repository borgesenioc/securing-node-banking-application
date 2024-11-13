const sqlite3 = require("sqlite3");
const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const helmet = require("helmet");
const { check, validationResult } = require("express-validator");

const db = new sqlite3.Database("./bank_sample.db");

const app = express();
const PORT = 3000;
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: "secret",
    resave: true,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      secure: true,
      samesite: 'lax'
    }
  })
);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.get("/", function (request, response) {
  response.sendFile(path.join(__dirname + "/html/login.html"));
});

app.use(helmet());
app.use(helmet({
  contentSecurityPolicy: false,
}));

// LOGIN SQL
app.post("/auth", function (request, response) {
  var username = request.body.username;
  var password = request.body.password;
  if (username && password) {
    db.get(
      `SELECT * FROM users WHERE username = ? AND password = ?`,
      [username, password],
      function (error, results) {
        console.log(error);
        console.log(results);
        if (results) {
          request.session.loggedin = true;
          request.session.username = results["username"];
          request.session.balance = results["balance"];
          request.session.file_history = results["file_history"];
          request.session.account_no = results["account_no"];
          response.redirect("/home");
        } else {
          response.send("Incorrect Username and/or Password!");
        }
        response.end();
      }
    );
  } else {
    response.send("Please enter Username and Password!");
    response.end();
  }
});

// Home Menu No Exploits Here.
app.get("/home", function (request, response) {
  if (request.session.loggedin) {
    const username = request.session.username;
    const balance = request.session.balance;
    response.render("home_page", { username, balance });
  } else {
    response.redirect("/");
  }
  response.end();
});

// CSRF CODE SECURED. SEE HEADERS SET ABOVE
app.get("/transfer", function (request, response) {
  if (request.session.loggedin) {
    const sent = "";
    response.render("transfer", { sent });
  } else {
    response.redirect("/");
  }
});

app.post("/transfer", function (request, response) {
  if (request.session.loggedin) {
    console.log("Transfer in progress");
    const balance = request.session.balance;
    const account_to = parseInt(request.body.account_to);
    const amount = parseInt(request.body.amount);
    const account_from = request.session.account_no;
    if (account_to && amount) {
      if (balance > amount) {
        db.get(
          `UPDATE users SET balance = balance + ? WHERE account_no = ?`,
          [amount, account_to],
          function (error) {
            console.log(error);
          }
        );
        db.get(
          `UPDATE users SET balance = balance - ? WHERE account_no = ?`,
          [amount, account_from],
          function (error) {
            console.log(error);
            const sent = "Money Transferred";
            response.render("transfer", { sent });
          }
        );
      } else {
        const sent = "You Don't Have Enough Funds.";
        response.render("transfer", { sent });
      }
    } else {
      const sent = "";
      response.render("transfer", { sent });
    }
  } else {
    response.redirect("/");
  }
});

// PATH TRAVERSAL PROTECTION
app.post("/download", function (request, response) {
  if (request.session.loggedin) {
    const file_name = request.body.file;

    // Setting the root directory path
    const root_directory = path.join(__dirname, "history_files");

    // Creating and normalizing the file path
    const filePath = path.join(root_directory, file_name);
    const normalizedPath = path.normalize(filePath);

    // Ensuring the file is within the root directory
    if (!normalizedPath.startsWith(root_directory + path.sep)) {
      response.end("File not found");
      return;
    }

    try {
      // Reading and serving the file content
      const content = fs.readFileSync(normalizedPath, "utf8");
      response.status(200).setHeader("Content-Type", "text/html");
      response.end(content);
    } catch (err) {
      console.log(err);
      response.end("File not found");
    }
  } else {
    response.redirect("/");
  }
});

// XSS CODE
app.get("/public_forum", function (request, response) {
  if (request.session.loggedin) {
    db.all(`SELECT username, message FROM public_forum`, (err, rows) => {
      console.log(rows);
      console.log(err);
      response.render("forum", { rows });
    });
  } else {
    response.redirect("/");
  }
});

app.post(
  "/public_forum",
  [
    check('comment')
      .trim()
      .escape()
      .notEmpty().withMessage('Comment cannot be empty')
      .isLength({ max: 500 }).withMessage('Comment cannot exceed 500 characters')
  ],
  function (request, response) {
    if (request.session.loggedin) {
      const errors = validationResult(request);
      if (!errors.isEmpty()) {
        return response.status(400).render("forum", { errors: errors.array() });
      }
      const comment = request.body.comment;
      const username = request.session.username;
      if (comment) {
        db.all(
          `INSERT INTO public_forum (username, message) VALUES (?, ?)`,
          [username, comment],
          (err) => {
            console.log(err);
          }
        );
        db.all(`SELECT username, message FROM public_forum`, (err, rows) => {
          console.log(rows);
          console.log(err);
          response.render("forum", { rows });
        });
      } else {
        db.all(`SELECT username, message FROM public_forum`, (err, rows) => {
          console.log(rows);
          console.log(err);
          response.render("forum", { rows });
        });
      }
    } else {
      response.redirect("/");
    }
  }
);

// SQL UNION INJECTION PROTECTION
app.get("/public_ledger", function (request, response) {
  if (request.session.loggedin) {
    const id = parseInt(request.query.id, 10);
    if (id) {
      db.all(
        `SELECT * FROM public_ledger WHERE from_account = ?`,
        [id],
        (err, rows) => {
          console.log("PROCESSING INPUT");
          console.log(err);
          if (rows) {
            response.render("ledger", { rows });
          } else {
            response.render("ledger", { rows });
          }
        }
      );
    } else {
      db.all(`SELECT * FROM public_ledger`, (err, rows) => {
        if (rows) {
          response.render("ledger", { rows });
        } else {
          response.render("ledger", { rows });
        }
      });
    }
  } else {
    response.redirect("/");
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port: ${PORT}`);
});