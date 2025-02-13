import jwt from 'jsonwebtoken';
export const authenticateToken = (req, res, next) => {
    // 1. Extract the token from the Authorization header
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format: "Bearer <token>"
    // 2. If no token is provided, return a 401 Unauthorized response
    if (!token) {
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }
    // 3. Verify the token
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            // 4. If the token is invalid or expired, return a 403 Forbidden response
            return res.status(403).json({ message: 'Invalid or expired token.' });
        }
        // 5. If the token is valid, attach the decoded payload to the request object
        const payload = decoded; // Type assertion
        req.user = { username: payload.username }; // Add user data to req.user
        next(); // Proceed to the next middleware or route handler
        return; // Explicitly return to satisfy TypeScript
    });
    return; // Explicitly return to satisfy TypeScript
};
