const express = require('express');
const bcrypt = require('bcryptjs');
const joi = require('joi');
const app = express();
const port = 3000;

import { Request, Response } from 'express';

interface UserDto {
  username: string;
  email?: string;
  type?: 'user' | 'admin';
  password: string;
}

interface UserEntry {
  email: string;
  type: 'user' | 'admin';
  salt: string;
  passwordhash: string;
}

// Database mock where the username is the primary key of a user.
const MEMORY_DB: Record<string, UserEntry> = {};

// I want to be able to register a new unique user (username and password). After the user is created I
// should be able to login with my username and password. If a user register request is invalid a 400 error
// should be returned, if the user is already registered a conflict error should be returned.
// On login the users crendentials should be verified.
// Because we dont have a database in this environment we store the users in memory. Fill the helper functions
// to query the memory db.

function getUserByUsername(name: string): UserEntry | undefined {
  if (name in MEMORY_DB) {
    return MEMORY_DB[name];
  }
  return undefined;
}

function getUserByEmail(email: string): UserEntry | undefined {
  let user: UserEntry | undefined = undefined;
  user = Object.values(MEMORY_DB).find((item) => item.email === email);
  return user;
}

// GET /register?username=test&email=test@test.com&type=user&password=gfjj33%FF

// POST /register
// {
//  username: 'test',
//  'email': 'test@test.com',
//  'type': 'user',
//  'password': 'gfjj33%FF',
// }

// POST (correct implementation of this case)
// app.post('/register', async (req: Request, res: Response) => {
app.get('/register', async (req: Request, res: Response) => {
  // Validate user object using joi
  // - username (required, min 3, max 24 characters)
  // - email (required, valid email address)
  // - type (required, select dropdown with either 'user' or 'admin')
  // - password (required, min 5, max 24 characters, upper and lower case, at least one special character)
  const schema = joi.object({
    username: joi.string().min(3).max(24).required(),
    password: joi
      .string()
      .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*?[^ws]).{5,24}$/)
      .min(5)
      .max(24)
      .required(),
    email: joi.string().email().required(),
    type: joi.string().valid('admin', 'user').required(),
  });

  //const userData: UserDto | any = req.body; // POST (correct implementation of this case)
  const userData: UserDto | any = req.query;

  const { error } = schema.validate(userData);
  if (error) return res.status(400).json({ error: 'Invalid user data' });
  else if (
    getUserByEmail(userData.email) ||
    getUserByUsername(userData.username)
  )
    return res.status(409).json({ error: 'User already exists' });
  else {
    const salt = await bcrypt.genSalt(10);
    const passwordhash = await bcrypt.hash(userData.password, salt);
    MEMORY_DB[userData.username] = {
      email: userData.email,
      type: userData.type,
      salt,
      passwordhash,
    };
  }
  res.status(200).json({ message: 'Success' });
});

// GET /login?username=test&password=gfjj33%FF

// POST /login
// {
//  username: 'test',
//  password: 'gfjj33%FF',
// }

// POST (correct implementation of this case)
// app.post('/login', async (req: Request, res: Response) => {
app.get('/login', async (req: Request, res: Response) => {
  //const userData: UserDto | any = req.body; // POST (correct implementation of this case)
  const userData: UserDto | any = req.query;
  const user = getUserByUsername(userData.username);

  // Return 200 if username and password match
  // Return 401 else
  if (user) {
    const validPassword = await bcrypt.compare(
      userData.password,
      user.passwordhash
    );
    if (validPassword) {
      return res.status(200).json({ message: 'Welcome!' });
    } else {
      return res.status(400).json({ error: 'Invalid Password' });
    }
  } else {
    return res.status(401).json({ error: 'User does not exist' });
  }
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
