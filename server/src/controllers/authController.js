import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import Joi from 'joi';
import { User } from '../models/User.js';

const registerSchema = Joi.object({
  name: Joi.string().min(2).max(60).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required()
});

export async function register(req, res, next) {
  try {
    const { value, error } = registerSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.message });

    const existing = await User.findOne({ email: value.email });
    if (existing) return res.status(409).json({ message: 'Email already used' });

    const passwordHash = await bcrypt.hash(value.password, 10);
    const user = await User.create({ name: value.name, email: value.email, passwordHash });
    const token = signToken(user);
    res.status(201).json({ token, user: publicUser(user) });
  } catch (err) { next(err); }
}

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

// TODO: implement login function
export async function login(req, res, next) {
  try 
  {
    const {email,password} = req.body;

    if(!email || !password)
    {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = await User.findOne({ email });

    if(!user){
      return res.status(401).json({ message: 'You are not registered' });
    }

    const isMatch = await user.comparePassword(password);

    if(!isMatch){
      return res.status(401).json({ message: 'Invalid Password entered' });
    }

    res.json({ token: signToken(user), user: publicUser(user) });

  }

  catch(error)
  {
    res.status(500).json({ message: 'Server Error' });
  }
}

export async function me(req, res) {
  const user = await User.findById(req.user.id).lean();
  res.json({ user: user && publicUser(user) });
}

function signToken(user) {
  const payload = { id: user._id.toString(), name: user.name, role: user.role };
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });
}

function publicUser(u) {
  return { id: u._id?.toString() || u.id, name: u.name, email: u.email, role: u.role };
}
