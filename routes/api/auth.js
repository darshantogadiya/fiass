const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const config = require("config");
const bcrypt = require('bcryptjs');
const {check, validationResult} = require('express-validator');
const auth = require('../../middleware/auth');

const User = require('../../models/User');


// @route    POST api/auth
// @desc     Test route
// @access   Public
router.get('/',auth,async (req,res)=>{
    try{
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    }
    catch(err){
        console.log(err.message);
        res.status(500).send('Server error');
    }
});

// @route    POST api/auth
// @desc     Auth route
// @access   Public
router.post('/',[
    check('email','include email').isEmail(),
    check('password','correct password required').exists("password required")
  ],
  async (req,res)=>{
      const errors = validationResult(req);
      if(!errors.isEmpty())
      {
          return res.status(400).json({errors:errors.array()});
      }
  
      const {email, password} = req.body;
  
      try
      {
          //see if user exists
          let user = await User.findOne({email});
  
          if(!user)
          {
              return res.status(400).json({errors:[{msg:'invalid id or password'}] });
          }
  
          const isMatch = await bcrypt.compare(password,user.password);
          if(!isMatch)
          {
            return res.status(400).json({errors:[{msg:'invalid id or password'}] });
          }

          //return JWT
          const payload ={
                  user:{
                      id: user.id,
                  }
          }
  
          jwt.sign(
              payload,
              config.get("jwtSecret"),
              {expiresIn:360000},
              (err,token) => {
                  if(err) throw err;
                  res.json({token});
              }
          );
      
      }
      catch(err)
      {
          console.log(err.message);
          res.status(500).send('Server error');
      }
      
  });

module.exports = router;