const express = require('express');
const mongoose = require('mongoose');
const ejs = require('ejs');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const session = require('express-session');
const flash = require('connect-flash');

const app = express();

mongoose.connect('mongodb://localhost:27017/myapp', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const User = mongoose.model('User', {
  username: String,
  password: String,
});

// Настройка Passport
passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const user = await User.findOne({ username: username });
    if (!user) {
      return done(null, false, { message: 'Incorrect username.' });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return done(null, false, { message: 'Incorrect password.' });
    }
    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id)
    .then(user => {
      done(null, user);
    })
    .catch(err => {
      done(err);
    });
});

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(session({
  secret: 'secret',
  resave: true,
  saveUninitialized: true,
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

app.get('/api/user/login', (req, res) => {
  res.render('login', { message: req.flash('error') });
});

app.post('/api/user/login', async (req, res, next) => {
  passport.authenticate('local', async (err, user, info) => {
    try {
      if (err) {
        throw err;
      }
      if (!user) {
        req.flash('error', 'Не верный логин или пароль');
        return res.redirect('/api/user/login');
      }
      req.logIn(user, (err) => {
        if (err) {
          throw err;
        }
        return res.redirect('/api/user/me');
      });
    } catch (error) {
      return next(error);
    }
  })(req, res, next);
});

app.get('/api/user/me', (req, res) => {
  if (req.isAuthenticated()) {
    User.findById(req.user._id)
      .then(user => {
        res.render('profile', { user: user });
      })
      .catch(err => {
        console.error(err);
        res.status(500).send('Internal Server Error');
      });
  } else {
    res.redirect('/api/user/login');
  }
});

app.get('/api/user/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error(err);
      res.status(500).send('Internal Server Error');
      return;
    }
    res.redirect('/api/user/login');
  });
});

app.get('/api/user/signup', (req, res) => {
  res.render('signup', { message: req.flash('error') });
});

app.post('/api/user/signup', (req, res) => {
  const { username, password, confirm_password } = req.body;

  if (password !== confirm_password) {
    req.flash('error', 'Пароли не совпадают');
    res.redirect('/api/user/signup');
    return;
  }

  User.findOne({ username: username })
    .then(existingUser => {
      if (existingUser) {
        req.flash('error', 'Такое имя пользователя уже занято');
        res.redirect('/api/user/signup');
        return;
      }

      return bcrypt.hash(password, 10);
    })
    .then(hashedPassword => {
      const newUser = new User({
        username: username,
        password: hashedPassword,
      });
      return newUser.save();
    })
    .then(newUser => {
      req.login(newUser, (err) => {
        if (err) throw err;
        res.redirect('/api/user/me');
      });
    })
    .catch(error => {
      req.flash('error', 'Что-то пошло не так');
      res.redirect('/api/user/signup');
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Сервер запущен порт: ${PORT}`);
});
