//Initiallising node modules
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const jwt = require('express-jwt');
const jwtGen = require('jsonwebtoken');
const randToken = require('rand-token');
require('dotenv').config();
const MongoClient = require('mongodb').MongoClient;
const ObjectID = require('mongodb').ObjectID;
const bcrypt = require('bcrypt');
let db; //Pool connection para no abrir y cerrar conexión en cada solicitud
const app = express();
const crypto = require('crypto');

//Connection MongoDB Atlas
const uri = `mongodb+srv://${process.env.USERDB}:${process.env.PASSWORD}@${process.env.CLUSTER}?retryWrites=true&w=majority`;
MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true }).connect(async (err, client) => {
  if (err) {
    console.log(err);
    throw err;
  }
  console.log('Conectado a MongoDB Atlas');
  db = await client.db(`${process.env.DATABASE}`);
});

const rawBodySaver = (req, res, buf, encoding) => {
  if (buf && buf.length) {
    req.rawBody = buf.toString(encoding || 'utf8');
  }
};

// Body Parser Middleware
app.use(bodyParser.json({ limit: '10mb', extended: true, verify: rawBodySaver }));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true, verify: rawBodySaver }));
app.use(bodyParser.raw({ verify: rawBodySaver, type: '*/*' }));

//CORS Middleware
app.use(cors());

//API Security
app.use(helmet());

//API Logger HTTP
app.use(morgan('combined'));

//Config JWT
const checkJwt = jwt({
  secret: process.env.SECRET,
  algorithms: ['HS256']
}).unless({ path: ['/login', { url: '/notificaciones', methods: ['POST'] }, { url: /^\/woocommerce\/.*/, methods: ['POST'] }, { url: '/fulljaus', methods: ['POST'] }] });

app.use(checkJwt);

//Setting up server
const server = app.listen(process.env.PORT || 9000, function () {
  const port = server.address().port;
  console.log('WS corriendo en el puerto:', port);
});

const requireUser = user => async (req, res, next) => {
  const datos = jwtGen.verify(req.headers.authorization.replace(/^Bearer\s/, ''), process.env.SECRET);
  if (datos.user && datos.user === user) {
    next();
  } else {
    res.status(401).send('Usuario no autorizado a acceder al servicio');
  }
};

//Valida firma para webhooks de Woocommerce
const processWebHookSignature = (secret, body, signature) => {
  let signatureComputed = crypto.createHmac('SHA256', secret).update(body).digest('base64');
  return ( signatureComputed === signature ) ? true : false;
}

//LOGIN
app.post('/login', async (req, res) => {
  const { user, password, refresh_token } = req.body;
  try {
    let resultPassword;
    let resultToken;
    let tiendas = [];
    //Si tengo password consulto a tabla login sino a la de tokens
    if (password) {
      //Primero busco si el usuario existe
      const resultUser = await db.collection('login').findOne({ user: String(user) });
      if (resultUser) {
        //Si existe comparo el password de la base con el pasado por HTTP
        resultPassword = await bcrypt.compare(password, resultUser.password);
        tiendas = resultUser.tiendas;
      } else {
        throw 'Usuario inexistente';
      }
    } else if (refresh_token) {
      //join en mongodb
      resultToken = await db.collection('tokens').aggregate([{
        $lookup: {
          from: 'login',
          let: { user: '$user', refresh_token: '$refresh_token' },
          pipeline: [{
            $match: {
              $expr: {
                $and: [
                  { $eq: ["$user", "$$user"] }, { $eq: ["$$refresh_token", refresh_token] }, { $eq: ["$$user", user] }
                ]
              }
            }
          }],
          as: 'logins'
        }
      }, {
        $match: { logins: { $ne: [] } } //Con esto lo transformo en un inner join
      }]);
      await resultToken.forEach(user => {
        if (user.user === 'admin') {
          tiendas = [1]; //No se usa cuando es admin
        } else {
          tiendas = user.logins[0].tiendas;
        }
      });
      if (tiendas.length === 0) {
        throw 'Refresh_token incorrecto';
      }
    } else throw 'Se necesita password o refresh_token';

    //Si el password o refresh_token es valido, genero el par de tokens
    if (resultToken || resultPassword) {
      const access_token = jwtGen.sign({ user, date: new Date(), tiendas }, process.env.SECRET, {
        expiresIn: '6h'
      });

      //Gereno un token random, porque si uso el sing, va a servir también para acceder a datos
      const refresh_token = randToken.uid(256);

      //Borro el actual y le asigno el nuevo par de tokens
      await db.collection('tokens').deleteMany({ user: String(user) }, async (err, result) => {
        if (err) throw err;
        await db.collection('tokens').insertOne({ user: String(user), access_token, refresh_token }, (err, result) => {
          if (err) throw err;
        });
      });
      //Mando ambos al usuario que hizo la solicitud
      res.status(200).json({ access_token, refresh_token });
    } else {
      throw 'Usuario y/o contraseña incorreta';
    }
  } catch (err) {
    console.log(err);
    res.status(401).send(err);
  }
});

//Agregar nuevo usuario para el ws - SOLO para user admin
app.post('/user', requireUser('admin'), (req, res) => {
  const { user, password, tiendas } = req.body;
  try {
    if (user && password && tiendas) {
      if (!Array.isArray(tiendas)) {
        throw 'Tiendas debe ser un array';
      } else if (tiendas.length === 0) {
        throw 'Debe informar por lo menos una tienda asociada al usuario a crear';
      }

      //Valido que tiendas sea numérico
      for (const tienda of tiendas) {
        if (typeof tienda !== 'number') {
          throw 'Los códigos de tiendas deben ser numéricos';
        }
      }

      db.collection('login').findOne({ user }, (err, result) => {
        if (err) throw err;
        if (!result) {
          bcrypt.genSalt(Number.parseInt(process.env.SALT_FACTOR), (err, salt) => {
            if (err) throw err;

            // hash password
            bcrypt.hash(password, salt, function (err, hash) {
              if (err) throw err;
              db.collection('login').insertOne({ user: String(user), password: hash, tiendas }, (err, result) => {
                if (err) throw err;
                res.sendStatus(200);
              });
            });
          });
        } else {
          res.status(500).send('Ya existe ese usuario');
        }
      });
    } else {
      throw 'Debe proporcionar user, password y tiendas a las que puede acceder';
    }
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
});

//Borrar usuario - SOLO ADMIN
app.delete('/user/:user', requireUser('admin'), async (req, res) => {
  const { user } = req.params;
  try {
    if (user && user != 'admin') {
      await db.collection('login').deleteOne({ user: String(user) }, async (err, result) => {
        if (err) throw err;
        await db.collection('tokens').deleteOne({ user: String(user) }, async (err, result) => {
          if (err) throw err;
          res.sendStatus(200);
        });
      });
    } else {
      throw 'Debe proporcionar user a eliminar';
    }
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
});

//Guardar notificaciones MELI
app.post('/notificaciones', (req, res) => {
  //IPs por las que MELI manda notifcaciones
  const MELIIPs = ['54.88.218.97', '18.215.140.160', '18.213.114.129', '18.213.114.129', '18.206.34.84', '216.33.196.25', '216.33.196.25', '::1', '127.0.0.1', '181.47.80.156'];
  var MELIIPsv6 = [];
  MELIIPs.forEach(ip => {
    MELIIPsv6.push(ip);
    if (ip !== '::1') {
      MELIIPsv6.push(`::ffff:${ip}`);
    }
  });
  const requestIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress || req.connection.socket.remoteAddress;
  if (MELIIPsv6.indexOf(requestIP) >= 0) {
    try {
      if (req.body.resource) {
        const data = { ...req.body, procesado: false, fecha: new Date() };
        db.collection("callbacks").insertOne(data, (err, result) => {
          if (err) throw err;
          res.sendStatus(200);
        });
      } else {
        throw 'No hay datos';
      }
    } catch (error) {
      console.log(error);
      res.sendStatus(500);
    }
  } else {
    res.status(401).send('IP Address unauthorized');
  }
});

//Guardar notificaciones Fulljaus
app.post('/fulljaus', (req, res) => {
    //Validar origen POST de alguna manera??
    if (true) {
      try {
        //if (req.body.result && req.body.result.length) {
          if(req.body.id){
          const data = { ...req.body, procesado: false, fecha: new Date(), user_id: Number.parseInt(req.body.seller.id), topic: 'orders'};
          db.collection('FJ_callbacks').insertOne(data, (err, result) => {
            if (err) throw err;
            res.sendStatus(200);
          });
        } else {
          throw 'No hay datos';
        }
      } catch (error) {
        console.log(error);
        res.sendStatus(500).send(error);
      }
    } else {
      console.log('Invalid signature');
      res.status(401).send('Invalid signature');
    }
});

//Guardar notificaciones WooCommerce
app.post('/woocommerce/:tienda', (req, res) => {
  if(req.headers['x-wc-webhook-resource']){
    //Valido firma
    const firmaOK = processWebHookSignature(process.env.WOOCOMMERCE_SECRET, req.rawBody, req.headers['x-wc-webhook-signature']);
    if (firmaOK) {
      try {
        if (req.headers['x-wc-webhook-resource']) {
          const data = { ...req.body, procesado: false, fecha: new Date(), user_id: Number.parseInt(req.params.tienda), evento: req.headers['x-wc-webhook-event'], topic: req.headers['x-wc-webhook-resource']};
          db.collection('WC_callbacks').insertOne(data, (err, result) => {
            if (err) throw err;
            res.sendStatus(200);
          });
        } else {
          throw 'No hay datos';
        }
      } catch (error) {
        console.log(error);
        res.sendStatus(500).send(error);
      }
    } else {
      console.log('Invalid signature');
      res.status(401).send('Invalid signature');
    }
  }else{
    res.status(500).send('No se envío el tipo de recurso');
  }
});

//Marca notificaciones procesadas
app.put('/notificaciones/:tipo?', async (req, res) => {
  try {
    if (req.body.data && Array.isArray(req.body.data)) {
      if (req.body.data.length === 0) {
        throw 'Debe informar por lo menos una notificación a procesar';
      }
      const tokenData = jwtGen.verify(req.headers.authorization.replace(/^Bearer\s/, ''), process.env.SECRET);
      const idFormat = req.body.data.map(id => new ObjectID(id));
      let filtro;
      if (tokenData.user == 'admin') {
        filtro = { _id: { $in: idFormat } };
      } else{
        filtro = { _id: { $in: idFormat }, user_id: { $in: tokenData.tiendas } };
      }
      const data = { $set: { procesado: true } };
      //Para MELI uso callbacks y si me mandan la tabla uso esa
      const collection = (req.params.tipo)? (req.params.tipo + '_') : '';
      await db.collection(collection + 'callbacks').updateMany(filtro, data, (err, result) => {
        if (err) throw err;
        res.status(200).json({ recibidos: req.body.data.length, procesados: result.result.n, modificados: result.result.nModified });
      });
    } else {
      throw 'Debe informar un array con las notificaciones a procesar';
    }
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
});

//Get notificaciones
app.get('/notificaciones/:cliente?', async (req, res) => {
  try {
    const tokenData = jwtGen.verify(req.headers.authorization.replace(/^Bearer\s/, ''), process.env.SECRET);
    //Filtro cliente, si no está, traigo la de todos - SOLO ADMIN
    let filtro = req.params.cliente ? { user_id: { $eq: Number.parseInt(req.params.cliente) } } : {};
    let projection = {};

    if (tokenData.user != 'admin') {
      filtro = req.params.cliente ? { $and: [{ user_id: Number.parseInt(req.params.cliente) }, { user_id: { $in: tokenData.tiendas } }] } : { user_id: { $in: tokenData.tiendas } };
    }

    //Tipo tienda
    const collection = (req.query.tipo)? (req.query.tipo + '_') : '';

    //Filtro pendientes
    if (req.query.pendientes) {
      filtro = { ...filtro, procesado: { $ne: true } };
    }

    //Filtro Fecha desde
    if (req.query.desde) {
      filtro = { ...filtro, fecha: { $gte: req.query.desde } };
    }

    //Filtro Fecha hasta
    if (req.query.hasta) {
      filtro = { ...filtro, fecha: { $lte: req.query.hasta } };
    }

    //Filtro topic
    if (req.query.topic) {
      filtro = { ...filtro, topic: { $eq: req.query.topic } };
    }

    //Filtro datos resumidos
    if (req.query.simple) {
      projection = { resource: 1 };
    }

    await db.collection(collection + 'callbacks').find(filtro).project(projection).limit(req.query.limit ? Number.parseInt(req.query.limit) : Number.parseInt(process.env.DEFAULT_LIMIT)).sort({ user_id: 1, fecha: 1 }).toArray((err, result) => {
      if (err) throw err;
      res.status(200).send(result);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});