// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const bcrypt = require('bcryptjs')
const Users = require('../users/users-model')
const router = require('express').Router()
const { checkPasswordLength, checkUsernameFree, checkUsernameExists } = require('../auth/auth-middleware')


router.get('/logout', (req, res, next) => {
  if(req.session.loggedInUser){
    req.session.destroy(err => {
      if(err){
        res.json({ message: err})
      } else {
        res.json({ message: 'logged out'})
      }
    })
  } else {
    res.status(200).json({ message: 'no session'})
  }
  
})

router.post('/register', checkPasswordLength, checkUsernameFree, (req, res, next) => {
  const { username, password } = req.body

  const hash = bcrypt.hashSync(password, 8)
  Users.add({username, password: hash})
    .then((id) => {
      res.status(201).json({ username, user_id: id.user_id})
    })
    .catch(next)
})

router.post('/login', checkPasswordLength, checkUsernameExists, async (req, res, next) => {
  try {
  const { username, password } = req.body;

  const result = await Users.findBy({ username }).first()

  if(result == null || !bcrypt.compareSync(password, result.password)){
    next({ status: 401, message: 'invalid credentials'})
    return;
  }

  req.session.loggedInUser = result;

  res.json({ message: `Welcome ${username}`})
} catch(err){
  next(err)
}
})




/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */


/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */


/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
router.use((err, req, res, next) =>{
  res.status(err.status || 500).json({
      message: err.message,
      stack: err.stack
  })
})


module.exports = router