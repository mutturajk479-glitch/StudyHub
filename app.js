const express = require("express");
const{DatabaseSync}=require("node:sqlite");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");


const app = express();

app.use(express.json());
app.use(express.static("public"));
// Connect to StudyHub database
const db = new DatabaseSync("studyhub.db");

// Create courses table
db.exec(`
    CREATE TABLE IF NOT EXISTS courses (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        duration TEXT NOT NULL
    )
`);

// Create users table
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'student'
    )
`);

// StudyHub courses
const courses = [
    {
        id: 1,
        name: "Python Programming",
        duration: "3 Months"
    },
    {
        id: 2,
        name: "Java Programming",
        duration: "4 Months"
    },
    {
        id: 3,
        name: "DSA",
        duration: "6 Months"
    }
];

// Save initial courses in database
const insertCourse = db.prepare(`
    INSERT OR IGNORE INTO courses (id, name, duration)
    VALUES (?, ?, ?)
`);

for (const course of courses) {
    insertCourse.run(
        course.id,
        course.name,
        course.duration
    );
}

// Home page
app.get("/", (req, res) => {
    res.send("Welcome to StudyHub!");
});

// Get all courses from database
app.get("/api/courses", (req, res) => {
    const courses = db.prepare(
        "SELECT * FROM courses"
    ).all();

    res.json(courses);
});



// Start server

// Add new course to database
app.post("/api/courses", authenticateToken,authorizeAdmin, (req, res) => {
    const { name, duration } = req.body;

    if (!name || !duration) {
        return res.status(400).json({
            message: "Name and duration are required"
        });
    }

    const result = db.prepare(
        "INSERT INTO courses (name, duration) VALUES (?, ?)"
    ).run(name, duration);

    const newCourse = db.prepare(
        "SELECT * FROM courses WHERE id = ?"
    ).get(result.lastInsertRowid);

    res.status(201).json({
        message: "Course added successfully",
        course: newCourse
    });
});






// Get one course from database
app.get("/api/courses/:id", (req, res) => {
    const courseId = Number(req.params.id);

    const course = db.prepare(
        "SELECT * FROM courses WHERE id = ?"
    ).get(courseId);

    if (!course) {
        return res.status(404).json({
            message: "Course not found"
        });
    }

    res.json(course);
});

// Update an existing course
app.put("/api/courses/:id",authenticateToken,authorizeAdmin, (req, res) => {
    const courseId = Number(req.params.id);
    const { name, duration } = req.body;

    if (!name || !duration) {
        return res.status(400).json({
            message: "Name and duration are required"
        });
    }

    const result = db.prepare(
        "UPDATE courses SET name = ?, duration = ? WHERE id = ?"
    ).run(name, duration, courseId);

    if (result.changes === 0) {
        return res.status(404).json({
            message: "Course not found"
        });
    }

    res.json({
        message: "Course updated successfully"
    });
});

// Delete a course
app.delete("/api/courses/:id",authenticateToken,authorizeAdmin, (req, res) => {
    const courseId = Number(req.params.id);

    if (!Number.isInteger(courseId) || courseId <= 0) {
        return res.status(400).json({
            message: "Invalid course ID"
        });
    }

    const result = db.prepare(
        "DELETE FROM courses WHERE id = ?"
    ).run(courseId);

    if (result.changes === 0) {
        return res.status(404).json({
            message: "Course not found"
        });
    }

    res.json({
        message: "Course deleted successfully"
    });
});

// Student Registration API
app.post("/api/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (
            typeof name !== "string" ||
            typeof email !== "string" ||
            typeof password !== "string" ||
            !name.trim() ||
            !email.trim() ||
            !password
        ) {
            return res.status(400).json({
                message: "Name, email and password are required"
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                message: "Password must be at least 8 characters"
            });
        }

        const cleanEmail = email.trim().toLowerCase();

        const hashedPassword = await bcrypt.hash(password, 10);

        const result = db.prepare(`
            INSERT INTO users (name, email, password_hash)
            VALUES (?, ?, ?)
        `).run(name.trim(), cleanEmail, hashedPassword);

        res.status(201).json({
            message: "Student registered successfully",
            user: {
                id: Number(result.lastInsertRowid),
                name: name.trim(),
                email: cleanEmail,
                role: "student"
            }
        });

    } catch (error) {
        if (error.message.includes("UNIQUE constraint failed")) {
            return res.status(409).json({
                message: "Email already registered"
            });
        }

        console.error(error);

        res.status(500).json({
            message: "Registration failed"
        });
    }
});

// Student Login API
app.post("/api/login", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            message: "Email and password are required"
        });
    }

    const user = db.prepare(
        "SELECT * FROM users WHERE email = ?"
    ).get(email.trim().toLowerCase());

    if (!user) {
        return res.status(401).json({
            message: "Invalid email or password"
        });
    }

    const passwordMatch = bcrypt.compareSync(
        password,
        user.password_hash
    );

    if (!passwordMatch) {
        return res.status(401).json({
            message: "Invalid email or password"
        });
    }

    const token = jwt.sign(
        {
            id: user.id,
            email: user.email,
            role: user.role
        },
        process.env.JWT_SECRET || "studyhub-local-demo-secret",
        { expiresIn: "1h" }
    );

    res.json({
        message: "Login successful",
        token: token,
        user: {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role
        }
    });
});

// Verify student login token
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            message: "Access denied. Please login."
        });
    }

    jwt.verify(
        token,
        process.env.JWT_SECRET || "studyhub-local-demo-secret",
        (err, user) => {
            if (err) {
                return res.status(403).json({
                    message: "Invalid or expired token"
                });
            }

            req.user = user;
            console.log("Verified token payload:",user);
            next();
        }
    );
}

// Check Admin Role
function authorizeAdmin(req, res, next) {
    if (req.user.role !== "admin") {
        return res.status(403).json({
            message: "Access denied. Admin only."
        });
    }

    next();
}

// Student profile API
app.get("/api/profile", authenticateToken, (req, res) => {
    const user = db.prepare(
        "SELECT id, name, email, role FROM users WHERE id = ?"
    ).get(req.user.id);

    if (!user) {
        return res.status(404).json({
            message: "Student not found"
        });
    }

    res.json({
        message: "Profile loaded successfully",
        user: user
    });
});

// Create Admin Account
const adminExists = db.prepare(
    "SELECT id FROM users WHERE email = ?"
).get("admin@studyhub.com");

if (!adminExists) {
    const hashedPassword = bcrypt.hashSync(
        "AdminStudyHub123",
        10
    );

    db.prepare(`
        INSERT INTO users (name, email, password_hash, role)
        VALUES (?, ?, ?, ?)
    `).run(
        "StudyHub Admin",
        "admin@studyhub.com",
        hashedPassword,
        "admin"
    );

    console.log("Admin account created!");
}

// Admin Dashboard API
app.get(
    "/api/admin/dashboard",
    authenticateToken,
    authorizeAdmin,
    (req, res) => {
        res.json({
            message: "Welcome to StudyHub Admin Dashboard",
            role: "admin"
        });
    }
);

// Create Quiz Results Table
db.prepare(`
    CREATE TABLE IF NOT EXISTS quiz_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        quiz_name TEXT NOT NULL,
        score INTEGER NOT NULL,
        total_questions INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
`).run();

console.log("Quiz results table is ready!");

// Save Quiz Result API
app.post(
    "/api/quiz-results",
    authenticateToken,
    (req, res) => {
        const { quiz_name, score, total_questions } = req.body;

        if (
            !quiz_name ||
            !Number.isInteger(score) ||
            !Number.isInteger(total_questions) ||
            total_questions <= 0 ||
            score < 0 ||
            score > total_questions
        ) {
            return res.status(400).json({
                message: "Invalid quiz result"
            });
        }

        const result = db.prepare(`
            INSERT INTO quiz_results
            (user_id, quiz_name, score, total_questions)
            VALUES (?, ?, ?, ?)
        `).run(
            req.user.id,
            quiz_name,
            score,
            total_questions
        );

        res.status(201).json({
            message: "Quiz result saved successfully!",
            resultId: Number(result.lastInsertRowid)
        });
    }
);

// Get Student Quiz Results API
app.get(
    "/api/quiz-results",
    authenticateToken,
    (req, res) => {
        const results = db.prepare(`
            SELECT quiz_name, score, total_questions, created_at
            FROM quiz_results
            WHERE user_id = ?
            ORDER BY id DESC
        `).all(req.user.id);

        res.json(results);
    }
);





app.listen(3000, () => {
    console.log("StudyHub server is running!");
});




