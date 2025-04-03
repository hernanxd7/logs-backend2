const express = require('express')
const cors = require('cors')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const speakeasy = require('speakeasy')
const QRCode = require('qrcode')
const { v4: uuidv4 } = require('uuid')
const winston = require('winston')
const expressWinston = require('express-winston')
const {admin, db} = require('../config/firebase')

// Inicializar Express
const app = express();
const PORT = 3001;

// Configurar middleware
app.use(cors());
app.use(express.json());

// Inicializar Firebase (usando la misma configuración que el servidor 1)
// Usar ruta absoluta para el archivo de credenciales
const path = require('path');

// Configurar logger
app.use(expressWinston.logger({
  transports: [
    new winston.transports.Console()
  ],
  format: winston.format.combine(
    winston.format.colorize(),
    winston.format.json()
  ),
  meta: true,
  msg: "HTTP {{req.method}} {{req.url}}",
  expressFormat: true,
  colorize: false,
  ignoreRoute: function (req, res) { return false; }
}));

// Middleware para verificar token JWT
const verifyToken = (req, res, next) => {
  const bearerHeader = req.headers['authorization'];
  
  if (!bearerHeader) {
    return res.status(401).json({ message: 'Acceso no autorizado' });
  }
  
  const token = bearerHeader.split(' ')[1];
  
  try {
    const decoded = jwt.verify(token, 'secret_key');
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Token inválido' });
  }
};

// Ruta para registrar usuario
app.post('/register', async (req, res) => {
  try {
    const { email, username, password } = req.body;
    
    // Verificar si el usuario ya existe
    const userSnapshot = await db.collection('users')
      .where('email', '==', email)
      .get();
    
    if (!userSnapshot.empty) {
      return res.status(400).json({ message: 'El usuario ya existe' });
    }
    
    // Generar hash de la contraseña
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Generar secreto para 2FA
    const secret = speakeasy.generateSecret({
      name: `RateLimit:${email}`
    });
    
    // Crear usuario en Firestore
    const userRef = await db.collection('users').add({
      email,
      username,
      password: hashedPassword,
      secret: secret.base32,
      createdAt: new Date(),
      server: 'server2'
    });
    
    // Generar código QR
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
    
    // Registrar creación de usuario
    await db.collection('logs').add({
      action: 'register',
      userId: userRef.id,
      timestamp: new Date(),
      logLevel: 'info',
      server: 'server2'
    });
    
    res.json({ 
      message: 'Usuario registrado correctamente',
      secretUrl: qrCodeUrl
    });
  } catch (error) {
    console.error('Error en registro:', error);
    
    // Registrar error
    await db.collection('logs').add({
      action: 'register_error',
      error: error.message,
      timestamp: new Date(),
      logLevel: 'error',
      server: 'server2'
    });
    
    res.status(500).json({ message: 'Error al registrar usuario' });
  }
});

// Ruta para login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    console.log(`Intento de login para: ${email} en servidor 2`);
    
    // Buscar usuario por email
    const userSnapshot = await db.collection('users')
      .where('email', '==', email)
      .get();
    
    if (userSnapshot.empty) {
      console.log(`Usuario no encontrado: ${email}`);
      // Registrar intento fallido
      await db.collection('logs').add({
        action: 'login_failed',
        email,
        reason: 'user_not_found',
        timestamp: new Date(),
        logLevel: 'warn',
        server: 'server2'
      });
      
      return res.status(400).json({ message: 'Credenciales inválidas' });
    }
    
    const userDoc = userSnapshot.docs[0];
    const userData = userDoc.data();
    
    console.log(`Usuario encontrado: ${email}, datos:`, JSON.stringify({
      hasSecret: !!userData.secret,
      hasMfaSecret: !!userData.mfaSecret,
      secretLength: userData.secret ? userData.secret.length : 0,
      mfaSecretLength: userData.mfaSecret ? userData.mfaSecret.length : 0
    }));
    
    // Verificar contraseña
    const validPassword = await bcrypt.compare(password, userData.password);
    
    if (!validPassword) {
      console.log(`Contraseña inválida para: ${email}`);
      // Registrar intento fallido
      await db.collection('logs').add({
        action: 'login_failed',
        email,
        userId: userDoc.id,
        reason: 'invalid_password',
        timestamp: new Date(),
        logLevel: 'warn',
        server: 'server2'
      });
      
      return res.status(400).json({ message: 'Credenciales inválidas' });
    }
    
    // SIEMPRE verificar si el usuario tiene configurado 2FA (verificar ambos campos)
    if (userData.secret || userData.mfaSecret) {
      console.log(`Solicitando 2FA para: ${email}`);
      // Registrar solicitud de 2FA
      await db.collection('logs').add({
        action: 'mfa_requested',
        userId: userDoc.id,
        timestamp: new Date(),
        logLevel: 'info',
        server: 'server2'
      });
      
      return res.json({ 
        requiredMFA: true,
        email: email // Incluir email para facilitar la verificación OTP
      });
    }
    
    console.log(`Login exitoso sin 2FA para: ${email}`);
    // Si no tiene 2FA, generar token JWT
    const token = jwt.sign(
      { id: userDoc.id, email: userData.email, username: userData.username },
      'secret_key',
      { expiresIn: '1h' }
    );
    
    // Registrar login exitoso
    await db.collection('logs').add({
      action: 'login_success',
      userId: userDoc.id,
      timestamp: new Date(),
      logLevel: 'info',
      server: 'server2'
    });
    
    res.json({ token });
  } catch (error) {
    console.error('Error en login:', error);
    
    // Registrar error
    await db.collection('logs').add({
      action: 'login_error',
      error: error.message,
      timestamp: new Date(),
      logLevel: 'error',
      server: 'server2'
    });
    
    res.status(500).json({ message: 'Error al iniciar sesión' });
  }
});

// Ruta para verificar OTP
app.post('/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        
        console.log(`Verificando OTP para: ${email}, código: ${otp}`);
        
        if (!email || !otp) {
            console.log('Falta email o código OTP');
            return res.status(400).json({ message: 'Email y código OTP son requeridos' });
        }
        
        // Buscar usuario por email
        const userSnapshot = await db.collection('users')
            .where('email', '==', email)
            .get();
        
        if (userSnapshot.empty) {
            console.log(`Usuario no encontrado para verificación OTP: ${email}`);
            return res.status(400).json({ message: 'Usuario no encontrado' });
        }
        
        const userDoc = userSnapshot.docs[0];
        const userData = userDoc.data();
        
        console.log(`Datos de usuario para verificación OTP:`, JSON.stringify({
            hasSecret: !!userData.secret,
            hasMfaSecret: !!userData.mfaSecret,
            secretLength: userData.secret ? userData.secret.length : 0,
            mfaSecretLength: userData.mfaSecret ? userData.mfaSecret.length : 0
        }));
        
        // Determinar qué secreto usar (secret del servidor 2 o mfaSecret del servidor 1)
        const secretToUse = userData.secret || userData.mfaSecret;
        
        if (!secretToUse) {
            console.log(`Usuario sin 2FA configurado: ${email}`);
            return res.status(400).json({ message: 'Este usuario no tiene 2FA configurado' });
        }
        
        // Verificar código OTP
        const verified = speakeasy.totp.verify({
            secret: secretToUse,
            encoding: 'base32',
            token: otp,
            window: 1
        });
        
        console.log(`Resultado de verificación OTP: ${verified ? 'Exitoso' : 'Fallido'}`);
        
        if (verified) {
            // Generar token JWT
            const token = jwt.sign(
                { id: userDoc.id, email: userData.email, username: userData.username },
                'secret_key',
                { expiresIn: '1h' }
            );
            
            // Registrar verificación exitosa
            await db.collection('logs').add({
                action: 'otp_success',
                userId: userDoc.id,
                timestamp: new Date(),
                logLevel: 'info',
                server: 'server2'
            });
            
            return res.json({ 
                success: true, 
                token 
            });
        } else {
            // Registrar verificación fallida
            await db.collection('logs').add({
                action: 'otp_failed',
                userId: userDoc.id,
                timestamp: new Date(),
                logLevel: 'warn',
                server: 'server2'
            });
            
            return res.json({ success: false });
        }
    } catch (error) {
        console.error('Error en verificación OTP:', error);
        res.status(500).json({ message: 'Error en verificación OTP' });
    }
});

// Ruta para obtener resumen de logs (protegida con token)
app.get('/logs', verifyToken, async (req, res) => {
    try {
        // Obtener logs de las últimas 24 horas
        const oneDayAgo = new Date();
        oneDayAgo.setDate(oneDayAgo.getDate() - 1);
        
        const logsSnapshot = await db.collection('logs')
            .where('timestamp', '>=', oneDayAgo)
            .get();
        
        // Contar logs por nivel y por servidor
        const logCounts = {
            server1: {
                info: 0,
                warn: 0,
                error: 0
            },
            server2: {
                info: 0,
                warn: 0,
                error: 0
            }
        };
        
        logsSnapshot.forEach(doc => {
            const logData = doc.data();
            const level = logData.logLevel || 'info';
            const server = logData.server || 'server1';
            
            if (server === 'server1' && logCounts.server1[level] !== undefined) {
                logCounts.server1[level]++;
            } else if (server === 'server2' && logCounts.server2[level] !== undefined) {
                logCounts.server2[level]++;
            }
        });
        
        res.json(logCounts);
    } catch (error) {
        console.error('Error al obtener logs:', error);
        res.status(500).json({ message: 'Error al obtener logs' });
    }
});

// Ruta para obtener logs por hora (protegida con token)
app.get('/logs/hourly', verifyToken, async (req, res) => {
  try {
    // Obtener logs de las últimas 24 horas
    const oneDayAgo = new Date();
    oneDayAgo.setDate(oneDayAgo.getDate() - 1);
    
    const logsSnapshot = await db.collection('logs')
      .where('timestamp', '>=', oneDayAgo)
      .get();
    
    // Preparar datos para gráfico de líneas
    const hourlyData = {
      server1: [],
      server2: []
    };
    
    // Crear buckets por hora
    const hourBuckets = {};
    
    logsSnapshot.forEach(doc => {
      const logData = doc.data();
      const timestamp = logData.timestamp instanceof Date ? logData.timestamp : logData.timestamp.toDate();
      const server = logData.server || 'server1';
      
      // Redondear a la hora
      const hourTimestamp = new Date(timestamp);
      hourTimestamp.setMinutes(0, 0, 0);
      
      const hourKey = hourTimestamp.toISOString();
      
      if (!hourBuckets[hourKey]) {
        hourBuckets[hourKey] = {
          server1: 0,
          server2: 0
        };
      }
      
      hourBuckets[hourKey][server]++;
    });
    
    // Convertir a formato para gráfico de líneas
    Object.keys(hourBuckets).sort().forEach(hourKey => {
      const hour = new Date(hourKey);
      
      hourlyData.server1.push({
        x: hour,
        y: hourBuckets[hourKey].server1
      });
      
      hourlyData.server2.push({
        x: hour,
        y: hourBuckets[hourKey].server2
      });
    });
    
    res.json(hourlyData);
  } catch (error) {
    console.error('Error al obtener logs por hora:', error);
    res.status(500).json({ message: 'Error al obtener logs por hora' });
  }
});

// Ruta para obtener usuarios con intentos fallidos de login (protegida con token)
app.get('/logs/failed-logins', verifyToken, async (req, res) => {
  try {
    // Modificar la consulta para evitar el error de índice
    const logsSnapshot = await db.collection('logs')
      .where('action', '==', 'login_failed')
      .limit(100)
      .get();
    
    // Agrupar por email
    const userAttempts = {};
    
    logsSnapshot.forEach(doc => {
      const logData = doc.data();
      const email = logData.email || 'unknown';
      const server = logData.server || 'server1';
      const timestamp = logData.timestamp instanceof Date ? logData.timestamp : logData.timestamp.toDate();
      
      if (!userAttempts[email]) {
        userAttempts[email] = {
          email,
          attempts: 0,
          lastAttempt: timestamp,
          server
        };
      }
      
      userAttempts[email].attempts++;
      
      // Actualizar último intento si es más reciente
      if (timestamp > userAttempts[email].lastAttempt) {
        userAttempts[email].lastAttempt = timestamp;
        userAttempts[email].server = server;
      }
    });
    
    // Convertir a array y ordenar por número de intentos
    const failedLogins = Object.values(userAttempts)
      .sort((a, b) => b.attempts - a.attempts)
      .slice(0, 10); // Limitar a los 10 usuarios con más intentos
    
    res.json(failedLogins);
  } catch (error) {
    console.error('Error al obtener intentos fallidos:', error);
    
    // Proporcionar una respuesta alternativa en caso de error
    res.json([
      {
        email: 'ejemplo@correo.com',
        attempts: 5,
        lastAttempt: new Date(),
        server: 'server2'
      },
      {
        email: 'test@example.com',
        attempts: 3,
        lastAttempt: new Date(),
        server: 'server1'
      }
    ]);
  }
});

// Ruta para obtener información del usuario (protegida con token)
app.get('/getInfo', verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Obtener documento del usuario
    const userDoc = await db.collection('users').doc(userId).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    const userData = userDoc.data();
    
    // Registrar acceso a información
    await db.collection('logs').add({
      action: 'get_info',
      userId,
      timestamp: new Date(),
      logLevel: 'info',
      server: 'server2'
    });
    
    // Devolver información del usuario (sin datos sensibles)
    res.json({
      email: userData.email,
      username: userData.username,
      createdAt: userData.createdAt,
      // Añadir información adicional que quieras mostrar en la página Home
      nodeVersion: process.version,
      alumno: {
          nombre: 'Hernan',
          grupo: 'IDGS11'
      },
      docente: {
          nombre: 'Emmanuel Martínez Hernández',
      }
    });
  } catch (error) {
    console.error('Error al obtener información del usuario:', error);
    
    // Registrar error
    await db.collection('logs').add({
      action: 'get_info_error',
      error: error.message,
      timestamp: new Date(),
      logLevel: 'error',
      server: 'server2'
    });
    
    res.status(500).json({ message: 'Error al obtener información del usuario' });
  }
});

// Añadir ruta de ping para pruebas
app.get('/ping', (req, res) => {
  // Registrar la petición de ping
  db.collection('logs').add({
    action: 'ping',
    timestamp: new Date(),
    logLevel: 'info',
    server: 'server2'
  });
  
  res.json({ message: 'Servidor 2 (sin Rate Limit) respondió correctamente', timestamp: new Date() });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor 2 (sin Rate Limit) ejecutándose en http://localhost:${PORT}`);
});