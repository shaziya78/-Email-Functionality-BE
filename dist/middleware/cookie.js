"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const authenticate = (req, res, next) => {
    // Parse cookies
    (0, cookie_parser_1.default)()(req, res, () => {
        const email = req.cookies.email; // Adjust the cookie name if necessary
        if (!email) {
            return res.status(401).json({ error: 'Not authenticated' });
        }
        req.userEmail = email; // Attach email to request object
        next();
    });
};
exports.default = authenticate;
