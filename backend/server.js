const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const path = require("path");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET =
    process.env.JWT_SECRET || "kelasyar-secret-key-2026";

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ======================================================
// DATABASE
// ======================================================

const dbPath = path.join(__dirname, "kelasyar.db");
const db = new Database(dbPath);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    school TEXT DEFAULT '',
    phone TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS classes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    grade TEXT DEFAULT '',
    created_at TEXT NOT NULL,

    FOREIGN KEY (user_id)
    REFERENCES users(id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS students (
    id TEXT PRIMARY KEY,
    class_id TEXT NOT NULL,
    name TEXT NOT NULL,
    code TEXT DEFAULT '',
    created_at TEXT NOT NULL,

    FOREIGN KEY (class_id)
    REFERENCES classes(id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS grades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    grade REAL NOT NULL,

    FOREIGN KEY (student_id)
    REFERENCES students(id)
    ON DELETE CASCADE,

    UNIQUE(student_id, position)
);

CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    class_id TEXT NOT NULL,
    student_id TEXT NOT NULL,
    date TEXT NOT NULL,
    status TEXT NOT NULL,

    FOREIGN KEY (class_id)
    REFERENCES classes(id)
    ON DELETE CASCADE,

    FOREIGN KEY (student_id)
    REFERENCES students(id)
    ON DELETE CASCADE,

    UNIQUE(student_id, date)
);
`);

console.log("SQLite database ready:");
console.log(dbPath);

// ======================================================
// HELPERS
// ======================================================

function createId() {
    return crypto.randomUUID();
}

function now() {
    return new Date().toISOString();
}

function createToken(user) {
    return jwt.sign(
        {
            id: user.id,
            email: user.email
        },
        JWT_SECRET,
        {
            expiresIn: "7d"
        }
    );
}

function authMiddleware(req, res, next) {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            return res.status(401).json({
                success: false,
                message: "لطفاً ابتدا وارد حساب کاربری شوید."
            });
        }

        const parts = authHeader.split(" ");

        if (
            parts.length !== 2 ||
            parts[0] !== "Bearer"
        ) {
            return res.status(401).json({
                success: false,
                message: "توکن نامعتبر است."
            });
        }

        const decoded = jwt.verify(
            parts[1],
            JWT_SECRET
        );

        req.user = decoded;

        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: "نشست شما منقضی شده است. دوباره وارد شوید."
        });
    }
}

function getClassForUser(classId, userId) {
    return db.prepare(`
        SELECT *
        FROM classes
        WHERE id = ?
        AND user_id = ?
    `).get(classId, userId);
}

// ======================================================
// HOME
// ======================================================

app.get("/", (req, res) => {
    res.json({
        success: true,
        message: "Kelasyar Backend is running",
        database: "SQLite",
        status: "online"
    });
});

// ======================================================
// STATUS
// ======================================================

app.get("/api/status", (req, res) => {
    res.json({
        success: true,
        assistant: "Kelasyar",
        status: "online",
        database: "SQLite"
    });
});

// ======================================================
// REGISTER
// ======================================================

app.post("/api/register", async (req, res) => {
    try {
        const {
            fullName,
            email,
            password
        } = req.body;

        if (!fullName || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "لطفاً تمام اطلاعات را وارد کنید."
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                message: "رمز عبور باید حداقل ۸ کاراکتر باشد."
            });
        }

        const normalizedEmail =
            email.trim().toLowerCase();

        const existingUser = db.prepare(`
            SELECT id
            FROM users
            WHERE email = ?
        `).get(normalizedEmail);

        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: "این ایمیل قبلاً ثبت شده است."
            });
        }

        const hashedPassword =
            await bcrypt.hash(password, 10);

        const userId = createId();

        db.prepare(`
            INSERT INTO users (
                id,
                full_name,
                email,
                password,
                school,
                phone,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(
            userId,
            fullName.trim(),
            normalizedEmail,
            hashedPassword,
            "",
            "",
            now()
        );

        res.status(201).json({
            success: true,
            message: "حساب کاربری با موفقیت ساخته شد.",
            user: {
                id: userId,
                fullName: fullName.trim(),
                email: normalizedEmail
            }
        });
    } catch (error) {
        console.error("Register Error:", error);

        res.status(500).json({
            success: false,
            message: "خطایی در ساخت حساب رخ داد."
        });
    }
});

// ======================================================
// LOGIN
// ======================================================

app.post("/api/login", async (req, res) => {
    try {
        const {
            email,
            password
        } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "ایمیل و رمز عبور را وارد کنید."
            });
        }

        const normalizedEmail =
            email.trim().toLowerCase();

        const user = db.prepare(`
            SELECT *
            FROM users
            WHERE email = ?
        `).get(normalizedEmail);

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "ایمیل یا رمز عبور اشتباه است."
            });
        }

        const passwordCorrect =
            await bcrypt.compare(
                password,
                user.password
            );

        if (!passwordCorrect) {
            return res.status(401).json({
                success: false,
                message: "ایمیل یا رمز عبور اشتباه است."
            });
        }

        const token = createToken(user);

        res.json({
            success: true,
            message: "ورود با موفقیت انجام شد.",
            token,
            user: {
                id: user.id,
                fullName: user.full_name,
                email: user.email
            }
        });
    } catch (error) {
        console.error("Login Error:", error);

        res.status(500).json({
            success: false,
            message: "خطایی هنگام ورود رخ داد."
        });
    }
});

// ======================================================
// ME
// ======================================================

app.get("/api/me", authMiddleware, (req, res) => {
    const user = db.prepare(`
        SELECT
            id,
            full_name,
            email,
            school,
            phone,
            created_at
        FROM users
        WHERE id = ?
    `).get(req.user.id);

    if (!user) {
        return res.status(404).json({
            success: false,
            message: "کاربر پیدا نشد."
        });
    }

    res.json({
        success: true,
        user: {
            id: user.id,
            fullName: user.full_name,
            email: user.email,
            school: user.school,
            phone: user.phone,
            createdAt: user.created_at
        }
    });
});

// ======================================================
// PROFILE
// ======================================================

app.get("/api/profile", authMiddleware, (req, res) => {
    const user = db.prepare(`
        SELECT
            id,
            full_name,
            email,
            school,
            phone
        FROM users
        WHERE id = ?
    `).get(req.user.id);

    if (!user) {
        return res.status(404).json({
            success: false,
            message: "کاربر پیدا نشد."
        });
    }

    res.json({
        success: true,
        profile: {
            id: user.id,
            fullName: user.full_name,
            email: user.email,
            school: user.school,
            phone: user.phone
        }
    });
});

app.put("/api/profile", authMiddleware, (req, res) => {
    try {
        const {
            fullName,
            school,
            phone
        } = req.body;

        if (!fullName || !fullName.trim()) {
            return res.status(400).json({
                success: false,
                message: "نام و نام خانوادگی الزامی است."
            });
        }

        db.prepare(`
            UPDATE users
            SET
                full_name = ?,
                school = ?,
                phone = ?
            WHERE id = ?
        `).run(
            fullName.trim(),
            school || "",
            phone || "",
            req.user.id
        );

        res.json({
            success: true,
            message: "پروفایل با موفقیت ذخیره شد."
        });
    } catch (error) {
        console.error("Profile Error:", error);

        res.status(500).json({
            success: false,
            message: "خطا در ذخیره پروفایل."
        });
    }
});

// ======================================================
// CLASSES - GET
// ======================================================

app.get("/api/classes", authMiddleware, (req, res) => {
    try {
        const classes = db.prepare(`
            SELECT
                id,
                name,
                grade,
                created_at
            FROM classes
            WHERE user_id = ?
            ORDER BY created_at DESC
        `).all(req.user.id);

        const result = classes.map(classItem => {
            const students = db.prepare(`
                SELECT
                    id,
                    name,
                    code,
                    created_at
                FROM students
                WHERE class_id = ?
                ORDER BY name ASC
            `).all(classItem.id);

            const studentsWithGrades =
                students.map(student => {
                    const grades = db.prepare(`
                        SELECT grade
                        FROM grades
                        WHERE student_id = ?
                        ORDER BY position ASC
                    `).all(student.id);

                    return {
                        id: student.id,
                        name: student.name,
                        code: student.code,
                        grades: grades.map(
                            g => g.grade
                        )
                    };
                });

            return {
                id: classItem.id,
                name: classItem.name,
                grade: classItem.grade,
                students: studentsWithGrades
            };
        });

        res.json({
            success: true,
            classes: result
        });
    } catch (error) {
        console.error("Get Classes Error:", error);

        res.status(500).json({
            success: false,
            message: "خطا در دریافت کلاس‌ها."
        });
    }
});

// ======================================================
// CREATE CLASS
// ======================================================

app.post("/api/classes", authMiddleware, (req, res) => {
    try {
        const {
            name,
            grade
        } = req.body;

        if (!name || !name.trim()) {
            return res.status(400).json({
                success: false,
                message: "نام کلاس را وارد کنید."
            });
        }

        const classId = createId();

        db.prepare(`
            INSERT INTO classes (
                id,
                user_id,
                name,
                grade,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
        `).run(
            classId,
            req.user.id,
            name.trim(),
            grade || "",
            now()
        );

        res.status(201).json({
            success: true,
            message: "کلاس با موفقیت ایجاد شد.",
            class: {
                id: classId,
                name: name.trim(),
                grade: grade || "",
                students: []
            }
        });
    } catch (error) {
        console.error("Create Class Error:", error);

        res.status(500).json({
            success: false,
            message: "خطا در ایجاد کلاس."
        });
    }
});

// ======================================================
// UPDATE CLASS
// ======================================================

app.put(
    "/api/classes/:classId",
    authMiddleware,
    (req, res) => {
        try {
            const classId = req.params.classId;

            const existingClass =
                getClassForUser(
                    classId,
                    req.user.id
                );

            if (!existingClass) {
                return res.status(404).json({
                    success: false,
                    message: "کلاس پیدا نشد."
                });
            }

            const {
                name,
                grade
            } = req.body;

            if (!name || !name.trim()) {
                return res.status(400).json({
                    success: false,
                    message: "نام کلاس الزامی است."
                });
            }

            db.prepare(`
                UPDATE classes
                SET
                    name = ?,
                    grade = ?
                WHERE id = ?
                AND user_id = ?
            `).run(
                name.trim(),
                grade || "",
                classId,
                req.user.id
            );

            res.json({
                success: true,
                message: "کلاس با موفقیت ویرایش شد."
            });
        } catch (error) {
            console.error("Update Class Error:", error);

            res.status(500).json({
                success: false,
                message: "خطا در ویرایش کلاس."
            });
        }
    }
);

// ======================================================
// DELETE CLASS
// ======================================================

app.delete(
    "/api/classes/:classId",
    authMiddleware,
    (req, res) => {
        try {
            const classId = req.params.classId;

            const existingClass =
                getClassForUser(
                    classId,
                    req.user.id
                );

            if (!existingClass) {
                return res.status(404).json({
                    success: false,
                    message: "کلاس پیدا نشد."
                });
            }

            db.prepare(`
                DELETE FROM classes
                WHERE id = ?
                AND user_id = ?
            `).run(
                classId,
                req.user.id
            );

            res.json({
                success: true,
                message: "کلاس حذف شد."
            });
        } catch (error) {
            console.error("Delete Class Error:", error);

            res.status(500).json({
                success: false,
                message: "خطا در حذف کلاس."
            });
        }
    }
);

// ======================================================
// STUDENTS - GET
// ======================================================

app.get(
    "/api/classes/:classId/students",
    authMiddleware,
    (req, res) => {
        try {
            const classId = req.params.classId;

            const classItem =
                getClassForUser(
                    classId,
                    req.user.id
                );

            if (!classItem) {
                return res.status(404).json({
                    success: false,
                    message: "کلاس پیدا نشد."
                });
            }

            const students = db.prepare(`
                SELECT
                    id,
                    name,
                    code,
                    created_at
                FROM students
                WHERE class_id = ?
                ORDER BY name ASC
            `).all(classId);

            const result = students.map(student => {
                const grades = db.prepare(`
                    SELECT grade
                    FROM grades
                    WHERE student_id = ?
                    ORDER BY position ASC
                `).all(student.id);

                return {
                    id: student.id,
                    name: student.name,
                    code: student.code,
                    grades: grades.map(
                        g => g.grade
                    )
                };
            });

            res.json({
                success: true,
                students: result
            });
        } catch (error) {
            console.error("Get Students Error:", error);

            res.status(500).json({
                success: false,
                message: "خطا در دریافت دانش‌آموزان."
            });
        }
    }
);

// ======================================================
// CREATE STUDENT
// ======================================================

app.post(
    "/api/classes/:classId/students",
    authMiddleware,
    (req, res) => {
        try {
            const classId = req.params.classId;

            const classItem =
                getClassForUser(
                    classId,
                    req.user.id
                );

            if (!classItem) {
                return res.status(404).json({
                    success: false,
                    message: "کلاس پیدا نشد."
                });
            }

            const {
                name,
                code
            } = req.body;

            if (!name || !name.trim()) {
                return res.status(400).json({
                    success: false,
                    message: "نام دانش‌آموز را وارد کنید."
                });
            }

            const studentId = createId();

            db.prepare(`
                INSERT INTO students (
                    id,
                    class_id,
                    name,
                    code,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?)
            `).run(
                studentId,
                classId,
                name.trim(),
                code || "",
                now()
            );

            res.status(201).json({
                success: true,
                message: "دانش‌آموز اضافه شد.",
                student: {
                    id: studentId,
                    name: name.trim(),
                    code: code || "",
                    grades: []
                }
            });
        } catch (error) {
            console.error(
                "Create Student Error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "خطا در اضافه کردن دانش‌آموز."
            });
        }
    }
);

// ======================================================
// UPDATE STUDENT
// ======================================================

app.put(
    "/api/students/:studentId",
    authMiddleware,
    (req, res) => {
        try {
            const studentId =
                req.params.studentId;

            const student = db.prepare(`
                SELECT
                    students.id,
                    classes.user_id
                FROM students
                INNER JOIN classes
                    ON students.class_id = classes.id
                WHERE students.id = ?
                AND classes.user_id = ?
            `).get(
                studentId,
                req.user.id
            );

            if (!student) {
                return res.status(404).json({
                    success: false,
                    message: "دانش‌آموز پیدا نشد."
                });
            }

            const {
                name,
                code
            } = req.body;

            if (!name || !name.trim()) {
                return res.status(400).json({
                    success: false,
                    message:
                        "نام دانش‌آموز الزامی است."
                });
            }

            db.prepare(`
                UPDATE students
                SET
                    name = ?,
                    code = ?
                WHERE id = ?
            `).run(
                name.trim(),
                code || "",
                studentId
            );

            res.json({
                success: true,
                message:
                    "اطلاعات دانش‌آموز ویرایش شد."
            });
        } catch (error) {
            console.error(
                "Update Student Error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "خطا در ویرایش دانش‌آموز."
            });
        }
    }
);

// ======================================================
// DELETE STUDENT
// ======================================================

app.delete(
    "/api/students/:studentId",
    authMiddleware,
    (req, res) => {
        try {
            const studentId =
                req.params.studentId;

            const student = db.prepare(`
                SELECT
                    students.id,
                    classes.user_id
                FROM students
                INNER JOIN classes
                    ON students.class_id = classes.id
                WHERE students.id = ?
                AND classes.user_id = ?
            `).get(
                studentId,
                req.user.id
            );

            if (!student) {
                return res.status(404).json({
                    success: false,
                    message: "دانش‌آموز پیدا نشد."
                });
            }

            db.prepare(`
                DELETE FROM students
                WHERE id = ?
            `).run(studentId);

            res.json({
                success: true,
                message: "دانش‌آموز حذف شد."
            });
        } catch (error) {
            console.error(
                "Delete Student Error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "خطا در حذف دانش‌آموز."
            });
        }
    }
);

// ======================================================
// GET GRADES
// ======================================================

app.get(
    "/api/students/:studentId/grades",
    authMiddleware,
    (req, res) => {
        try {
            const studentId =
                req.params.studentId;

            const student = db.prepare(`
                SELECT
                    students.id,
                    classes.user_id
                FROM students
                INNER JOIN classes
                    ON students.class_id = classes.id
                WHERE students.id = ?
                AND classes.user_id = ?
            `).get(
                studentId,
                req.user.id
            );

            if (!student) {
                return res.status(404).json({
                    success: false,
                    message: "دانش‌آموز پیدا نشد."
                });
            }

            const grades = db.prepare(`
                SELECT
                    grade
                FROM grades
                WHERE student_id = ?
                ORDER BY position ASC
            `).all(studentId);

            res.json({
                success: true,
                grades: grades.map(
                    g => g.grade
                )
            });
        } catch (error) {
            console.error(
                "Get Grades Error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "خطا در دریافت نمرات."
            });
        }
    }
);

// ======================================================
// SAVE GRADES
// ======================================================

app.put(
    "/api/students/:studentId/grades",
    authMiddleware,
    (req, res) => {
        try {
            const studentId =
                req.params.studentId;

            const student = db.prepare(`
                SELECT
                    students.id,
                    classes.user_id
                FROM students
                INNER JOIN classes
                    ON students.class_id = classes.id
                WHERE students.id = ?
                AND classes.user_id = ?
            `).get(
                studentId,
                req.user.id
            );

            if (!student) {
                return res.status(404).json({
                    success: false,
                    message: "دانش‌آموز پیدا نشد."
                });
            }

            const grades =
                Array.isArray(req.body.grades)
                    ? req.body.grades
                    : [];

            for (const grade of grades) {
                if (
                    grade === null ||
                    grade === "" ||
                    grade === undefined
                ) {
                    continue;
                }

                const numberGrade =
                    Number(grade);

                if (
                    Number.isNaN(numberGrade) ||
                    numberGrade < 0 ||
                    numberGrade > 20
                ) {
                    return res.status(400).json({
                        success: false,
                        message:
                            "نمره باید بین ۰ تا ۲۰ باشد."
                    });
                }
            }

            const saveGrades =
                db.transaction(() => {
                    db.prepare(`
                        DELETE FROM grades
                        WHERE student_id = ?
                    `).run(studentId);

                    const insertGrade =
                        db.prepare(`
                            INSERT INTO grades (
                                student_id,
                                position,
                                grade
                            )
                            VALUES (?, ?, ?)
                        `);

                    grades.forEach(
                        (grade, index) => {
                            if (
                                grade === null ||
                                grade === "" ||
                                grade === undefined
                            ) {
                                return;
                            }

                            insertGrade.run(
                                studentId,
                                index + 1,
                                Number(grade)
                            );
                        }
                    );
                });

            saveGrades();

            res.json({
                success: true,
                message:
                    "نمرات با موفقیت ذخیره شدند."
            });
        } catch (error) {
            console.error(
                "Save Grades Error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "خطا در ذخیره نمرات."
            });
        }
    }
);

// ======================================================
// GET ATTENDANCE
// ======================================================

app.get(
    "/api/classes/:classId/attendance",
    authMiddleware,
    (req, res) => {
        try {
            const classId =
                req.params.classId;

            const date = req.query.date;

            if (!date) {
                return res.status(400).json({
                    success: false,
                    message:
                        "تاریخ مشخص نشده است."
                });
            }

            const classItem =
                getClassForUser(
                    classId,
                    req.user.id
                );

            if (!classItem) {
                return res.status(404).json({
                    success: false,
                    message: "کلاس پیدا نشد."
                });
            }

            const records = db.prepare(`
                SELECT
                    student_id,
                    status
                FROM attendance
                WHERE class_id = ?
                AND date = ?
            `).all(
                classId,
                date
            );

            const result = {};

            records.forEach(record => {
                result[record.student_id] =
                    record.status;
            });

            res.json({
                success: true,
                date,
                records: result
            });
        } catch (error) {
            console.error(
                "Get Attendance Error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "خطا در دریافت حضور و غیاب."
            });
        }
    }
);

// ======================================================
// SAVE ATTENDANCE
// ======================================================

app.put(
    "/api/classes/:classId/attendance",
    authMiddleware,
    (req, res) => {
        try {
            const classId =
                req.params.classId;

            const {
                date,
                records
            } = req.body;

            if (!date) {
                return res.status(400).json({
                    success: false,
                    message:
                        "تاریخ مشخص نشده است."
                });
            }

            if (
                !records ||
                typeof records !== "object"
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "اطلاعات حضور و غیاب نامعتبر است."
                });
            }

            const classItem =
                getClassForUser(
                    classId,
                    req.user.id
                );

            if (!classItem) {
                return res.status(404).json({
                    success: false,
                    message: "کلاس پیدا نشد."
                });
            }

            const saveAttendance =
                db.transaction(() => {
                    const studentCheck =
                        db.prepare(`
                            SELECT id
                            FROM students
                            WHERE id = ?
                            AND class_id = ?
                        `);

                    const insertAttendance =
                        db.prepare(`
                            INSERT INTO attendance (
                                class_id,
                                student_id,
                                date,
                                status
                            )
                            VALUES (?, ?, ?, ?)
                            ON CONFLICT(student_id, date)
                            DO UPDATE SET
                                status =
                                    excluded.status
                        `);

                    for (
                        const studentId
                        of Object.keys(records)
                    ) {
                        const status =
                            records[studentId];

                        if (
                            ![
                                "present",
                                "absent",
                                "late"
                            ].includes(status)
                        ) {
                            continue;
                        }

                        const student =
                            studentCheck.get(
                                studentId,
                                classId
                            );

                        if (!student) {
                            continue;
                        }

                        insertAttendance.run(
                            classId,
                            studentId,
                            date,
                            status
                        );
                    }
                });

            saveAttendance();

            res.json({
                success: true,
                message:
                    "حضور و غیاب با موفقیت ذخیره شد."
            });
        } catch (error) {
            console.error(
                "Save Attendance Error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "خطا در ذخیره حضور و غیاب."
            });
        }
    }
);

// ======================================================
// ATTENDANCE HISTORY
// ======================================================

app.get(
    "/api/classes/:classId/attendance/history",
    authMiddleware,
    (req, res) => {
        try {
            const classId =
                req.params.classId;

            const classItem =
                getClassForUser(
                    classId,
                    req.user.id
                );

            if (!classItem) {
                return res.status(404).json({
                    success: false,
                    message: "کلاس پیدا نشد."
                });
            }

            const history = db.prepare(`
                SELECT
                    date,
                    student_id,
                    status
                FROM attendance
                WHERE class_id = ?
                ORDER BY date DESC
            `).all(classId);

            res.json({
                success: true,
                history
            });
        } catch (error) {
            console.error(
                "Attendance History Error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "خطا در دریافت تاریخچه حضور و غیاب."
            });
        }
    }
);

// ======================================================
// DASHBOARD
// ======================================================

app.get(
    "/api/dashboard",
    authMiddleware,
    (req, res) => {
        try {
            const classCount = db.prepare(`
                SELECT COUNT(*) AS count
                FROM classes
                WHERE user_id = ?
            `).get(req.user.id).count;

            const studentCount = db.prepare(`
                SELECT COUNT(*) AS count
                FROM students
                INNER JOIN classes
                    ON students.class_id = classes.id
                WHERE classes.user_id = ?
            `).get(req.user.id).count;

            const gradeCount = db.prepare(`
                SELECT COUNT(*) AS count
                FROM grades
                INNER JOIN students
                    ON grades.student_id = students.id
                INNER JOIN classes
                    ON students.class_id = classes.id
                WHERE classes.user_id = ?
            `).get(req.user.id).count;

            const attendanceCount = db.prepare(`
                SELECT COUNT(*) AS count
                FROM attendance
                INNER JOIN classes
                    ON attendance.class_id = classes.id
                WHERE classes.user_id = ?
            `).get(req.user.id).count;

            res.json({
                success: true,
                stats: {
                    classes: classCount,
                    students: studentCount,
                    grades: gradeCount,
                    attendance: attendanceCount
                }
            });
        } catch (error) {
            console.error(
                "Dashboard Error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "خطا در دریافت آمار داشبورد."
            });
        }
    }
);

// ======================================================
// 404
// ======================================================

app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: "مسیر مورد نظر پیدا نشد."
    });
});

// ======================================================
// START SERVER - IMPORTANT FOR RENDER
// ======================================================

app.listen(
    PORT,
    "0.0.0.0",
    () => {
        console.log("");
        console.log(
            "================================="
        );
        console.log(
            "       KELASYAR BACKEND"
        );
        console.log(
            "================================="
        );
        console.log(
            `Server running on port ${PORT}`
        );
        console.log(
            "Database: SQLite"
        );
        console.log(
            "Status: ONLINE"
        );
        console.log(
            "================================="
        );
        console.log("");
    }
);