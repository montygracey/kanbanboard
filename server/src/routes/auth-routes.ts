import { Router, Request, Response } from 'express';
import { User } from '../models/user.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

// Define an interface for the request body
interface LoginRequestBody {
  username: string;
  password: string;
}

// Explicitly define the return type of the login function
export const login = async (req: Request<{}, {}, LoginRequestBody>, res: Response): Promise<Response> => {
  const { username, password } = req.body;

  try {
    // 1. Find the user by username
    const user = await User.findOne({ where: { username } });

    // 2. If the user doesn't exist, return an error
    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password.' });
    }

    // 3. Compare the provided password with the hashed password in the database
    const isPasswordValid = await bcrypt.compare(password, user.password);

    // 4. If the password is invalid, return an error
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid username or password.' });
    }

    // 5. Generate a JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username }, // Payload
      process.env.JWT_SECRET as string, // Secret key
      { expiresIn: '1h' } // Token expiration
    );

    // 6. Return the token to the client
    return res.json({ token });
  } catch (error: unknown) {
    // Explicitly type the error
    if (error instanceof Error) {
      console.error('Error during login:', error.message);
    } else {
      console.error('Unknown error during login:', error);
    }
    return res.status(500).json({ message: 'An error occurred during login.' });
  }
};

const router = Router();

// POST /login - Login a user
router.post('/login', login);

export default router;