import express from "express";
import jwt  from "jsonwebtoken";
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import cookieParser from "cookie-parser";
import mysql from 'mysql2'

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express()
const port = 5000

app.use(express.static("public"));
app.use(express.json());
app.use(cookieParser());

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'usuarios',
  });

app.get("/", (req, res) => {
  res.redirect("/login");
});

// Ruta para mostrar el login HTML
app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/public/login.html");
});

// Ruta para mostrar el login HTML
app.get("/protected", (req, res) => {
  res.sendFile(__dirname + "/public/protected.html");
});

app.get("/register", (req, res) => {
    res.sendFile(__dirname + "/public/register.html");
  });

// Ruta de inicio de sesión
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Realiza una consulta a la base de datos para verificar las credenciales del usuario
  const query = "SELECT * FROM users WHERE username = ? AND password = ?";
  db.query(query, [username, password], (err, results) => {
    if (err) {
      console.error("Error al verificar las credenciales: " + err.message);
      res.sendStatus(500);
    } else if (results.length === 1) {
      const user = {
        id: results[0].id,
        username: results[0].username,
      };

      // Genera un token y almacénalo en una cookie
      const token = jwt.sign({ user }, "secretkey", { expiresIn: "120s" });
      res.cookie("token", token, { httpOnly: false, maxAge: 120000 }); // Almacena el token en una cookie

      res.json({ message: "Inicio de sesión exitoso" });
    } else {
      res.sendStatus(401); // Credenciales inválidas
    }
  });
});

app.post("/register", (req, res) => {
    const { username, password } = req.body;
    const query = 'INSERT INTO users (username, password) VALUES (?, ?)';
    db.query(query, [username, password], (err, results) => {
        if (err) {
            console.log(err.message)
            return res.status(500).json({ error: err.message });
        }

        res.json({ message: 'Usuario registrado exitosamente' });
    });
});

app.post('/protected',verifyToken, (req,res) =>{
    jwt.verify(req.token,'secretkey',(error,authData)=>{
        if(error){
            res.sendStatus(403)
        }
        else{
            const decodedToken = jwt.decode(req.token, { complete: true });
            res.json({
                message: `${decodedToken.payload.user.username}`
            })
        }
    })
})

function verifyToken(req, res, next) {
    const token = req.cookies.token;
  
    if (token) {
      req.token = token;
      next();
    } else {
      res.sendStatus(403); // Acceso no autorizado
    }
  }

app.listen(port, () => {
    console.log(`Servidor en ejecución en http://localhost:${port}`);
  });
