import React, { Fragment, useState } from 'react'
import { Link } from 'react-router-dom';

const Login = () => {
    const [formData, setFormData] = useState({
        email:'',
        password:'',
    });

    const {email,password} = formData;

    const onChange = e => setFormData({...formData, [e.target.name]:e.target.value});

    const onSubmit = async e=>{
        e.preventDefault();
        if(password.toString().length<4)
        {

            console.log('please enter valid password');
        }
        else
        {
            console.log("SUCCESS");
            // const newUser ={
            //     name,
            //     email,
            //     password,
            // }

            // try {
            //     const config = {
            //         headers:{
            //             'Content-Type':'application/json'
            //         }
            //     }
            //     const body = JSON.stringify(newUser);
            //     console.log(body);
            //     const res = await axios.post('/api/users', body, config);
            //     console.log(res.data);
            // } catch (err) {
            //     console.error(err.response.data);
            // }
        }
    }
    return <section className="container">
        <Fragment>
            <h1 className="large text-primary">Sign In</h1>
            <p className="lead"><i className="fas fa-user"></i> Sign in into Your Account</p>
            <form className="form" onSubmit={e=>onSubmit(e)}>
                <div className="form-group">
                <input type="email" placeholder="Email Address" value={email} onChange={e=> onChange(e)} name="email" />
                <small className="form-text"
                    >This site uses Gravatar so if you want a profile image, use a
                    Gravatar email</small>
                </div>
                <div className="form-group">
                <input
                    type="password"
                    placeholder="Password"
                    name="password"
                    value={password} 
                    onChange={e=> onChange(e)}
                    minLength="6"
                />
                </div>
                <input type="submit" className="btn btn-primary" value="Login" />
            </form>
            <p className="my-1">
               Don't have an account? <Link to="/register">Sign up</Link>
            </p>
        </Fragment>
        </section>;
}

export default Login
