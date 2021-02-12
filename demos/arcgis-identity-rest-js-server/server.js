require("cross-fetch/polyfill");
require("isomorphic-form-data");
const express = require("express");
const session = require("express-session");
const FileStore = require("session-file-store")(session);
const app = express();
const { UserSession } = require("@esri/arcgis-rest-auth");
const {
  CLIENT_ID,
  SESSION_SECRET,
  ENCRYPTION_KEY,
  REDIRECT_URI,
} = require("./config.json");

const credentials = {
  clientId: CLIENT_ID,
  redirectUri: REDIRECT_URI,
};

app.use(
  // setup sessions, express will set a cookie on the client
  // to keep track of a session id and rehydrate the
  // correstponding session on the server.
  session({
    name: "dev-summit-demo",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 2592000000, // 30 days in milliseconds
    },

    // store session data in a secure, encrypted file
    // sessions will be loaded from these files and decrypted
    // at the end of every request the state of `request.session`
    // will be saved back to disk.
    store: new FileStore({
      ttl: 2592000000 / 1000, // 30 days in seconds
      retries: 1,
      secret: ENCRYPTION_KEY,

      // custom encoding and decoding for sessions means we can
      // initalize a single `UserSession` object for use with rest js
      encoder: (sessionObj) => {
        if (typeof sessionObj.userSession !== "string") {
          sessionObj.userSession = sessionObj.userSession.serialize();
        }

        return JSON.stringify(sessionObj);
      },
      decoder: (sessionContents) => {
        if (!sessionContents) {
          return { userSession: null };
        }

        const sessionObj =
          typeof sessionContents === "string"
            ? JSON.parse(sessionContents)
            : sessionContents;

        if (typeof sessionObj.userSession === "string") {
          sessionObj.userSession = UserSession.deserialize(
            sessionObj.userSession
          );
        }
        return sessionObj;
      },
    }),
  })
);

app.get("/sign-in", function (req, res) {
  UserSession.authorize(credentials, res);
});

app.get("/sign-out", function (req, res) {
  // currently only destroys the cookie and session file
  // does not revoke tokens
  // https://github.com/Esri/arcgis-rest-js/issues/800
  req.session.destroy();
  res.redirect("/");
});

app.get("/authenticate", async function (req, res) {
  req.session.userSession = await UserSession.exchangeAuthorizationCode(
    {
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
    },
    req.query.code
  );

  req.session.save(function (err) {
    res.redirect("/");
  });
});

app.get("/", function (req, res) {
  if (req.session.userSession) {
    res.send(`
    <h1>Hi ${req.session.userSession.username}<h1>
    <pre><code>${JSON.stringify(req.session.userSession, null, 2)}</code></pre>
    <a href="/sign-out">Sign Out<a>
  `);
  } else {
    res.send(`<a href="/sign-in">Sign In<a>`);
  }
});

app.listen(3000, function () {
  console.log(`Visit http://localhost:3000/ to get started!`);
});
