import { Request, Response, NextFunction } from 'express';
import cookieParser from 'cookie-parser';

const authenticate = (req: Request, res: Response, next: NextFunction) => {
  // Parse cookies
  cookieParser()(req, res, () => {
    const email = req.cookies.email; // Adjust the cookie name if necessary

    if (!email) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    (req as any).userEmail = email; // Attach email to request object
    next();
  });
};

export default authenticate;
