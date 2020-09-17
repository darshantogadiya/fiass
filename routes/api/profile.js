const express = require('express');
const router = express.Router();
const request = require('request');
const config = require('config');
const auth = require('../../middleware/auth');
const Profile = require('../../models/Profile') ;
const {check, validationResult} = require('express-validator');
const User = require('../../models/User');
const { ValidatorsImpl } = require('express-validator/src/chain');


// @route    GET api/profile/me
// @desc     get current user's profile
// @access   Private
router.get('/me',auth,async (req,res)=>{
    try{
        const profile = await Profile.findOne({user:req.user.id}).populate('user',['name','avatar']);

        if(!profile)
        {
            return res.status(400).json({msg:"No profile found"}); 
        }
    }
    catch(err)
    {
        console.log(err.message);
        res.status(500).send('Server error');
    }
});

// @route    POST api/profile/
// @desc     Create/Update User profile
// @access   Private
router.post('/',[auth,
    [check('status','Status is required').not().isEmpty(),check('skills','Skills is required').not().isEmpty()]],
    async (req,res)=>{
        const errors=validationResult(req);
        if(!errors.isEmpty())
        {
            return res.status(400).json({errors: errors.array()});
        }

        const {
            company,
            website,
            location,
            bio,
            status,
            githubusername,
            skills,
            youtube,
            facebook,
            twitter,
            instagram,
            linkedin,
        } = req.body;

        //Build Profile objects
        const profileFields = {};
        profileFields.user = req.user.id;
        if(company) profileFields.company = company;
        if(website) profileFields.webiste = website;
        if(location) profileFields.location = location;
        if(bio) profileFields.bio = bio;
        if(status) profileFields.status = status;
        if(githubusername) profileFields.githubusername = githubusername;
        if(skills)
        {
            profileFields.skills = skills.split(',').map(skill=>skill.trim());   
        }

        //buidl social object
        profileFields.social ={}
        if(youtube) profileFields.social.youtube = youtube;
        if(facebook) profileFields.social.facebook = facebook;
        if(twitter) profileFields.social.twitter = twitter;
        if(instagram) profileFields.social.instagram = instagram;
        if(linkedin) profileFields.social.linkedin = linkedin;

        try
        {
            let profile = await Profile.findOne({user:req.user.id});

            if(profile)
            {
                //update
                profile = await Profile.findOneAndUpdate({user:req.user.id},{$set:profileFields},{new:true});
                return res.json(profile);
            }

            //create
            profile = new Profile(profileFields);

            await profile.save();
            return res.json(profile);

            
        }
        catch(err)
        {
            console.log(err.message);
            res.status(500).send('Server error');
        }
});

// @route    GET api/profile/
// @desc     Get all profiles
// @access   Public
router.get('/',async (req,res)=>{
    try {
        const profiles = await Profile.find().populate('user',['name','avatar']);
        res.json(profiles);
    } catch (err) {
        console.log(err.message);
        res.status(500).send('Server error');
    }
});

// @route    GET api/profile/user/:user_id
// @desc     Get all profile by user_id
// @access   Public
router.get('/user/:user_id',async (req,res)=>{
    try {
        const profile = await Profile.findOne({user: req.params.user_id}).populate('user',['name','avatar']);
        if(!profile)
        {
            return res.status(400).json('No profile found'); 
        }
        res.json(profile);
    } catch (err) {
        console.log(err.message);
        if(err.kind == 'ObjectId')
        {
            return res.status(400).json('No profile found'); 
        }
        res.status(500).send('Server error');
    }
});


// @route    GET api/profile/
// @desc     Get all profiles
// @access   Public
router.get('/',async (req,res)=>{
    try {
        const profiles = await Profile.find().populate('user',['name','avatar']);
        res.json(profiles);
    } catch (err) {
        console.log(err.message);
        res.status(500).send('Server error');
    }
});

// @route    DELETE api/profile/
// @desc     Delete profile,user and posts
// @access   Private
router.delete('/',auth,async (req,res)=>{
    try {
        // @todo - remove posts
        await Profile.findOneAndRemove({user: req.user.id});
        await User.findOneAndRemove({_id: req.user.id});
        res.json({msg:"User is gone"});
    } catch (err) {
        console.log(err.message);
        res.status(500).send('Server error');
    }
});

// @route    PUT api/profile/experience
// @desc     Add profile experience
// @access   Private
router.put('/experience',[auth,[
    check('title','title is required').not().isEmpty(),
    check('company','company is required').not().isEmpty(),
    check('from','from date is required').not().isEmpty()
]],
async (req, res)=>{
    const errors = validationResult(req);
    if(!errors.isEmpty())
    {
        return res.status(400).json({errors:console.errors.array()});
    }

    const{
        title,
        company,
        lcoation, 
        from,
        to,
        current,
        description
    } = req.body;

    const newExp ={
        title,
        company,
        lcoation, 
        from,
        to,
        current,
        description
    };
    try {
        const profile = await Profile.findOne({user: req.user.id});

        profile.experience.unshift(newExp);
        await profile.save();
        res.json(profile);
    } catch (err) {
        console.log(err.message);
        res.status(500).send('Server error');
    }
});

// @route    DELETE api/profile/experience/:exp_id
// @desc     Remove profile experience
// @access   Private
router.delete('/experience/:exp_id',auth,async (req,res) =>{
    try {
        const profile = await Profile.findOne({user: req.user.id});
        
        //get remove index
        const removeIndex = profile.experience.map(item => item.id).indexOf(req.params.exp_id);
        profile.experience.splice(removeIndex,1);
        await profile.save();
        res.json(profile);
    } catch (err) {
        console.log(err.message);
        res.status(500).send('Server error');
    }
});

// @route    PUT api/profile/education
// @desc     Add profile education
// @access   Private
router.put('/education',[auth,[
    check('school','school is required').not().isEmpty(),
    check('degree','degree is required').not().isEmpty(),
    check('fieldOfStudy','field of study is required').not().isEmpty(),
    check('from','from date is required').not().isEmpty()
]],
async (req, res)=>{
    const errors = validationResult(req);
    if(!errors.isEmpty())
    {
        return res.status(400).json({errors:console.errors.array()});
    }

    const{
        school,
        degree,
        fieldOfStudy, 
        from,
        to,
        current,
        description
    } = req.body;

    const newEdu ={
        school,
        degree,
        fieldOfStudy, 
        from,
        to,
        current,
        description
    };
    try {
        const profile = await Profile.findOne({user: req.user.id});

        profile.education.unshift(newEdu);
        await profile.save();
        res.json(profile);
    } catch (err) {
        console.log(err.message);
        res.status(500).send('Server error');
    }
});

// @route    DELETE api/profile/education/:edu_id
// @desc     Remove profile education
// @access   Private
router.delete('/education/:edu_id',auth,async (req,res) =>{
    try {
        const profile = await Profile.findOne({user: req.user.id});
        
        //get remove index
        const removeIndex = profile.education.map(item => item.id).indexOf(req.params.edu_id);
        profile.education .splice(removeIndex,1);
        await profile.save();
        res.json(profile);
    } catch (err) {
        console.log(err.message);
        res.status(500).send('Server error');
    }
});

// @route    GET api/profile/github/:username
// @desc     get user repos
// @access   public
router.get('/github/:username',async (req,res) =>{
    try {
        const options = {
            uri:`http://api.github.com/users/${req.params.username}/repos?per_page=5&
            sort=created:asc&client_id=${config.get('githubClientId')}&client_secret=${config.get('githubSecret')}`,
            method: 'GET',
            headers: {'user-agent':'node.js'}
        };

        request(options, (errors,response,body) =>{
            if(errors) console.error(error);

            if(response.statusCode!=200)
            {
                return res.status(404).json({msg:'github profile not found'});
            }

            res.json(JSON.parse(body));
        })
    } catch (err) {
        console.log(err.message);
        res.status(500).send('Server error');
    }
});

module.exports = router;