require('dotenv').config();
const express = require('express');
const app = express();
const mysql = require('mysql');
const port = 3000;
const cors = require('cors');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');

app.use(cors());
app.use(express.json());    


//Definições do banco de dados
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'db',
});

//middleware

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Extrai o token do cabeçalho Authorization
    if (!token) {
        return res.status(401).send('Token não fornecido');
    }
    jwt.verify(token, process.env.SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).send('Token inválido');
        }
        req.user = decoded;
        next();
    });
}


//Rota para informar a porta da API
app.get('/user/:id', checkToken, async (req, res) => {
    res.send('O token foi verificado com sucesso!');
});

//Rota protegida que requer autenticação
app.get("/protected", checkToken, (req, res) => {
    res.send("Rota protegida acessada com sucesso!");
});

//Registrar usuário
app.post("/register", (req, res) => {
    const { user, password } = req.body;
    db.query("SELECT * FROM users_db WHERE user = ?", [user], (err, result) => {
        if (err) {
                return res.status(500).send('A API retornou erro ao verificar usuário ' + err);
            }
            if (result.length > 0) {
                return res.status(400).send('Usuário já existe');
            }
            if (!user || !password) {
                return res.status(400).send('Usuário e senha são obrigatórios');
            }
            if  (result.length === 0) {
                bcrypt.hash(password, saltRounds, (err, hash) => {
            if (err) {
                return res.status(500).send('A API retornou erro ao criptografar senha ' + err);
                }
                // Inserir usuário e senha criptografada no banco de dados
                db.query("INSERT INTO users_db (user, password) VALUES (?, ?)", [user, hash], (err, result) => {
                if (err) {
                return res.status(500).send('A API retornou erro ao registrar usuário ' + err);
                }
                res.status(201).send('Usuário registrado com sucesso');         
            });
         });                
        }
    });
});


//Login do usuário
app.post("/auth/login", (req, res) => {
    const { user, password } = req.body;
    db.query("SELECT * FROM users_db WHERE user = ?", [user] , (err, result) => {;
        if (err) {
            req.send('A API retornou erro ao buscar usuário ' + err);
        }
        if (result.length > 0) {
            console.log('if da hash');
            bcrypt.compare(password, result[0].password, (err, result) => {
                if (err) {
                    console.log('primeiro if');
                    return res.status(500).send('A API retornou erro ao comparar senha ' + err);
                }
                if (result) {
                    console.log('segundo if');
                    try {
                        const secret = process.env.SECRET;
                        console.log('secret: ' + secret);
                    if (!secret) {
                        throw new Error('Variável SECRET não definida');
                    }
                        const token = jwt.sign(
                        { id: user._id },
                        secret,
                        { expiresIn: '4h' }
                        );
                        res.status(200).json({
                        message: 'Usuário autenticado com sucesso',
                        token: token,
                        user: user
                    });
                    } catch (error) {
                        console.error('Erro ao autenticar usuário:', error.message);
                        res.status(500).json({
                        message: 'Erro ao autenticar usuário',
                        error: error.message
                });
            }
        }
            });
        } else {
            console.log('else');
            res.status(401).send('Usuário ou senha incorretos');
        }
    });
});


app.listen(port, () => {
console.log(`Servidor rodando em http://localhost:${port}`);
});
