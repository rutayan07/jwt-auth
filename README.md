# 🚀 Complete MERN Authentication System

### 🔐 JWT Auth • 📧 Email Verification • 🔁 Password Reset

A full-stack authentication system built using the MERN stack (MongoDB, Express, React, Node.js). This project implements secure user authentication with JWT, email verification, and password reset functionality using Nodemailer.

This is a complete production-style application with both frontend and backend fully developed and connected.

---

## 📂 Project Structure

```bash
root/
│
├── client1/                 # React Frontend (Vite)
│   └── src/
│       ├── assets/
│       ├── components/
│       ├── context/
│       ├── pages/
│       ├── App.jsx
│       ├── main.jsx
│       └── index.css
│
├── server/                  # Node.js Backend (Express)
│   ├── config/
│   ├── controllers/
│   ├── middleware/
│   ├── models/
│   ├── routes/
│   ├── .env
│   └── server.js
```

---

## ✨ Features

### 🔐 Authentication

* User Registration & Login
* JWT-based Authentication
* Protected Routes

### 📧 Email System

* Email Verification (Token-based)
* Forgot Password (Email Link)
* Reset Password with Expiry Token

### ⚙️ Backend

* REST API with Express.js
* MVC Architecture
* MongoDB with Mongoose
* Nodemailer Email Service
* Authentication Middleware

### ⚛️ Frontend

* React (Vite)
* Context API (Global State)
* Clean UI with Page Routing

---

## 🛠️ Tech Stack

**Frontend**

* React (Vite)
* Context API
* CSS

**Backend**

* Node.js
* Express.js
* MongoDB
* Mongoose
* JWT
* Nodemailer
* Bcrypt

---

## ⚙️ How to Run the Project

### 🔹 1. Clone the Repository

```bash
git clone https://github.com/rutayan07/jwt-auth
cd jwt-auth
```

---

## 🖥️ Start Backend Server

```bash
cd server
npm install
```

### Create `.env` file inside `/server`:

```env
PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_secret_key

EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password
CLIENT_URL=http://localhost:5173
```

### Run Backend

```bash
npm run dev     # if using nodemon
# OR
npm start
```

✅ Backend will run on:
👉 http://localhost:5000

---

## 🌐 Start Frontend

Open a new terminal:

```bash
cd client1
npm install
npm run dev
```

✅ Frontend will run on:
👉 http://localhost:5173

---

## 🔗 Connecting Frontend & Backend

Make sure:

* Backend is running on port **5000**
* Frontend API calls point to:

```
http://localhost:5000/api
```

---

## 📌 API Endpoints

| Method | Endpoint                  | Description      |
| ------ | ------------------------- | ---------------- |
| POST   | /api/auth/register        | Register user    |
| POST   | /api/auth/login           | Login user       |
| POST   | /api/auth/verify-email    | Verify email     |
| POST   | /api/auth/forgot-password | Send reset email |
| POST   | /api/auth/reset-password  | Reset password   |

---

## 🔒 Security Features

* Password hashing using bcrypt
* JWT authentication
* Email verification before login
* Secure reset tokens with expiry
* Protected routes via middleware

---

## 🚀 Future Improvements

* Google OAuth Login
* Refresh Token System
* Role-Based Access Control
* Deployment (AWS / Azure)

---

## 👨‍💻 Author

**Rutayan Patra**

---

## 📄 License

MIT License
