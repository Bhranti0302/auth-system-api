# 🔐 Advanced Authentication System (MERN Backend)

A production-ready authentication system built with Node.js, Express, MongoDB, and JWT. This project implements modern security practices like refresh tokens, Google OAuth, email verification, and brute-force protection.

---

## 🚀 Features

### 🔑 Authentication
- User Signup & Login (JWT-based)
- Secure Password Hashing using bcrypt
- Access Token + Refresh Token system
- Refresh Token Rotation

### 🔐 Security
- Strong Password Validation (Regex enforced)
- Brute-force protection (login attempts + account lock)
- HTTP-only secure cookies
- Token versioning (logout from all devices)
- Timing attack protection

### 📧 Email System
- Email Verification on Signup
- Forgot Password (Reset via email link)
- Secure password reset with expiry

### 🔁 Session Management
- Refresh Token stored in DB
- Logout from single device
- Logout from all devices

### 🌐 Social Login
- Google OAuth Login

---

## 🏗️ Tech Stack

- Backend: Node.js, Express.js  
- Database: MongoDB (Mongoose)  
- Authentication: JWT  
- Security: bcrypt, crypto  
- OAuth: Google Auth Library  
- Email: Nodemailer  
- Session Store: connect-mongo  

---

## 📁 Project Structure

project/
│
├── controllers/
│   └── authController.js
│
├── models/
│   └── User.js
│
├── routes/
│   └── authRoutes.js
│
├── utils/
│   ├── generateToken.js
│   ├── sendEmail.js
│   └── cookieOptions.js
│
├── app.js
├── server.js
└── .env

---

## ⚙️ Environment Variables

Create a `.env` file:

PORT=5000

MONGO_URI=your_mongodb_connection

JWT_SECRET=your_access_token_secret  
JWT_REFRESH_SECRET=your_refresh_token_secret  

GOOGLE_CLIENT_ID=your_google_client_id  

EMAIL_USER=your_email  
EMAIL_PASS=your_email_password  

NODE_ENV=development  

---

## 🔌 API Endpoints

### Auth Routes

| Method | Endpoint | Description |
|--------|---------|------------|
| POST | /api/auth/signup | Register user |
| POST | /api/auth/login | Login user |
| POST | /api/auth/google-login | Google login |
| POST | /api/auth/refresh-token | Get new access token |
| POST | /api/auth/logout | Logout user |
| GET  | /api/auth/verify-email | Verify email |

### Password Routes

| Method | Endpoint | Description |
|--------|---------|------------|
| POST | /api/auth/forgot-password | Send reset link |
| POST | /api/auth/reset-password/:token | Reset password |
| POST | /api/auth/change-password | Change password |

---

## 🔐 Password Rules

- Minimum 8 characters  
- At least 1 uppercase letter  
- At least 1 lowercase letter  
- At least 1 number  
- At least 1 special character  

---

## ▶️ Getting Started

### 1. Clone the repo
git clone https://github.com/your-username/auth-system.git  
cd auth-system  

### 2. Install dependencies
npm install  

### 3. Run server
npm run dev  

---

## 🧪 Testing

- Postman  
- Thunder Client  
- Frontend integration  

---

## 📌 Future Improvements

- Add frontend (React + Tailwind)  
- Role-based authorization  
- Rate limiting  
- Two-factor authentication (2FA)  
- Docker support  

---

## 📜 License

MIT License  

---

## ⭐ Support

If you like this project, give it a ⭐ on GitHub!
