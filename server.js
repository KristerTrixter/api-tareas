const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs').promises;
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const SECRET_KEY = process.env.JWT_SECRET || "fbb93c8446dce74ee2813f2d39f4b2f6287d20d909044a43d1cb2fc4d8213c8c"
const usuarios = [];

const app = express();
const PORT = 3000;

// Middleware para analizar JSON en el cuerpo de las peticiones
app.use(bodyParser.json());

// Funciones asíncronas para leer y escribir en tareas.json
async function obtenerTareas() {
    try {
        const data = await fs.readFile('tareas.json', 'utf8');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') {
            await guardarTareas([]);
            return [];
        }
        throw error;
    }
}

async function guardarTareas(tareas) {
    await fs.writeFile('tareas.json', JSON.stringify(tareas, null, 2), 'utf8');
}

// Ruta POST /register: registra un nuevo usuario con contraseña encriptada
app.post('/register', async (req, res, next) => {
    try {
        const { username, password } = req.body;

        if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
            return res.status(400).json({ error: 'Usuario y contraseña válidos son requeridos' });
        }

        const usuarioExiste = usuarios.find(u => u.username === username);
        if (usuarioExiste) {
            return res.status(400).json({ error: 'El nombre de usuario ya está registrado' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const nuevoUsuario = {
            id: Date.now(),
            username: username.trim(),
            password: hashedPassword
        };

        usuarios.push(nuevoUsuario);
        res.status(201).json({ mensaje: 'Usuario registrado exitosamente', username: nuevoUsuario.username });
    } catch (error) {
        next(error);
    }
});

// Ruta POST /login: autentica al usuario y devuelve un token JWT
app.post('/login', async (req, res, next) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
        }

        const usuario = usuarios.find(u => u.username === username);
        if (!usuario) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        const passwordValido = await bcrypt.compare(password, usuario.password);
        if (!passwordValido) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        const token = jwt.sign({ id: usuario.id, username: usuario.username }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ mensaje: 'Inicio de sesión exitoso', token });
    } catch (error) {
        next(error);
    }
});

// Middleware de autenticación para proteger rutas mediante JWT
function autenticarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    // Soporta tanto "Bearer <token>" como el token directo en el header
    const token = authHeader && authHeader.startsWith('Bearer ')
        ? authHeader.split(' ')[1]
        : authHeader;

    if (!token) {
        return res.status(401).json({ error: 'Acceso denegado: token no proporcionado' });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido o expirado' });
        }
        req.user = user;
        next();
    });
}

// Middleware personalizado para validar los datos de las tareas
const validarTarea = (req, res, next) => {
    const { titulo, descripcion } = req.body;
    if (!titulo || typeof titulo !== 'string' || titulo.trim() === '' ||
        !descripcion || typeof descripcion !== 'string' || descripcion.trim() === '') {
        return res.status(400).json({ error: 'El título y la descripción son obligatorios y deben ser texto válido' });
    }
    next();
};

// Ruta GET /tareas: devuelve todas las tareas
app.get('/tareas', autenticarToken, async (req, res, next) => {
    try {
        const tareas = await obtenerTareas();
        res.json(tareas);
    } catch (error) {
        next(error);
    }
});

// Ruta POST /tareas: agrega una nueva tarea con título y descripción
app.post('/tareas', autenticarToken, validarTarea, async (req, res, next) => {
    try {
        const { titulo, descripcion } = req.body;
        const tareas = await obtenerTareas();
        const nuevaTarea = {
            id: Date.now(),
            titulo: titulo.trim(),
            descripcion: descripcion.trim()
        };
        tareas.push(nuevaTarea);
        await guardarTareas(tareas);
        res.status(201).json({ mensaje: 'Tarea creada', tarea: nuevaTarea });
    } catch (error) {
        next(error);
    }
});

// Ruta PUT /tareas/:id: actualiza una tarea existente según el id proporcionado
app.put('/tareas/:id', autenticarToken, validarTarea, async (req, res, next) => {
    try {
        const { id } = req.params;
        const { titulo, descripcion } = req.body;
        const tareas = await obtenerTareas();
        const indice = tareas.findIndex(t => t.id === Number(id));

        if (indice === -1) {
            return res.status(404).json({ error: 'Tarea no encontrada' });
        }

        tareas[indice] = {
            ...tareas[indice],
            titulo: titulo.trim(),
            descripcion: descripcion.trim()
        };

        await guardarTareas(tareas);
        res.json({ mensaje: 'Tarea actualizada', tarea: tareas[indice] });
    } catch (error) {
        next(error);
    }
});

// Ruta DELETE /tareas/:id: elimina una tarea según el id proporcionado
app.delete('/tareas/:id', autenticarToken, async (req, res, next) => {    try {
        const { id } = req.params;
        const tareas = await obtenerTareas();
        const tareasFiltradas = tareas.filter(t => t.id !== Number(id));

        if (tareas.length === tareasFiltradas.length) {
            return res.status(404).json({ error: 'Tarea no encontrada' });
        }

        await guardarTareas(tareasFiltradas);
        res.json({ mensaje: 'Tarea eliminada' });
    } catch (error) {
        next(error);
    }
});

// Ruta POST /tareas: agrega una nueva tarea con título y descripción
app.post('/tareas', validarTarea, async (req, res, next) => {
    try {
        const { titulo, descripcion } = req.body;
        const nuevaTarea = {
            id: Date.now(),
            titulo: titulo.trim(),
            descripcion: descripcion.trim()
        };
        // Aquí conectaremos guardarTareas() en el inciso d
        res.status(201).json({ mensaje: 'Tarea creada', tarea: nuevaTarea });
    } catch (error) {
        next(error);
    }
});

// Ruta PUT /tareas/:id: actualiza una tarea existente según el id proporcionado
app.put('/tareas/:id', validarTarea, async (req, res, next) => {
    try {
        const { id } = req.params;
        const { titulo, descripcion } = req.body;
        // Aquí conectaremos obtenerTareas() y guardarTareas() en el inciso d
        res.json({ mensaje: `Tarea ${id} actualizada`, tarea: { id: Number(id), titulo: titulo.trim(), descripcion: descripcion.trim() } });
    } catch (error) {
        next(error);
    }
});

// Ruta DELETE /tareas/:id: elimina una tarea según el id proporcionado
app.delete('/tareas/:id', async (req, res, next) => {
    try {
        const { id } = req.params;
        // Aquí conectaremos obtenerTareas() y guardarTareas() en el inciso d
        res.json({ mensaje: `Tarea ${id} eliminada` });
    } catch (error) {
        next(error);
    }
});

// Ruta de prueba inicial
app.get('/', (req, res) => {
    res.json({ mensaje: 'API de gestión de tareas funcionando correctamente' });
});

// Middleware para manejar rutas no encontradas (404 Not Found)
app.use((req, res) => {
    res.status(404).json({ error: `Ruta no encontrada: ${req.method} ${req.originalUrl}` });
});

// Middleware personalizado para manejo de errores (JSON malformado y errores del servidor)
app.use((err, req, res, next) => {
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        return res.status(400).json({ error: 'Formato JSON inválido en la petición' });
    }
    console.error(err.stack);
    res.status(500).json({ error: 'Error interno del servidor' });
});

app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
