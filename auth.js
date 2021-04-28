const passport = require('passport');
const LocalStrategy = require('passport-local');
const bcrypt = require('bcrypt');
const ObjectID = require('mongodb').ObjectID;
const GitHubStrategy = require('passport-github').Strategy;

module.exports = (app, db) => {
    passport.serializeUser((user, done) => {
        done(null, user._id);
    });

    passport.deserializeUser((id, done) => {
        db.findOne(
            {
                _id: new ObjectID(id)
            }, (err, doc) => {
                if (err)
                    return done(err, null);
                done(null, doc);
            });
    });

    passport.use(new LocalStrategy(
        function(username, password, done) {
            db.findOne(
                {
                    username: username
                }, (err, user) => {
                    console.log('User '
                        + username
                        + ' attempted to log in.');
                    if (err)
                        return done(err);
                    if (!user)
                        return done(null, false);
                    if (!bcrypt.compareSync(password, user.password))
                        return done(null, false);
                    return done(null, user);
                });
        }
    ));

    passport.use(new GitHubStrategy({
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: 'https://boilerplate-advancednode.ahmedkhfagy.repl.co/auth/github/callback'
    },
        (accessToken, refreshToken, profile, cb) => {
            db.findAndModify(
                { id: profile.id },
                {},
                {
                    $setOnInsert: {
                        id: profile.id,
                        name: profile.displayName || 'Ahmed',
                        photo: profile.photos[0].value || '',
                        email: Array.isArray(profile.emails) ? profile.emails[0].value : 'No public email',
                        created_on: new Date(),
                        provider: profile.provider || ''
                    },
                    $set: {
                        last_login: new Date()
                    },
                    $inc: {
                        login_count: 1
                    }
                },
                { upsert: true, new: true },
                (err, doc) => {
                    return cb(null, doc.value);
                }
            );
        }
    ));
};