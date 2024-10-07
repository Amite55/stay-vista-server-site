const express = require('express')
const app = express()
require('dotenv').config()
const nodemailer = require("nodemailer");
const cors = require('cors')
const cookieParser = require('cookie-parser')
const { MongoClient, ServerApiVersion, ObjectId, RunCommandCursor, Timestamp } = require('mongodb')
const jwt = require('jsonwebtoken');
const { errorMonitor } = require('nodemailer/lib/xoauth2');
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const port = process.env.PORT || 8000

// middleware
const corsOptions = {
  origin: ['http://localhost:5173', 'http://localhost:5174'],
  credentials: true,
  optionSuccessStatus: 200,
}
app.use(cors(corsOptions))

app.use(express.json())
app.use(cookieParser())

// email send to user ============
const sendEmail = async (emailAddress, emailData) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    host: "smtp.gmail.com",
    port: 587,
    secure: false, // Use `true` for port 465, `false` for all other ports
    auth: {
      user: process.env.TRANSPORTER_EMAIL,
      pass: process.env.TRANSPORTER_PASS,
    },
  });
  const mailBody = {
    from: `"StayVista👻" <${process.env.TRANSPORTER_EMAIL}>`, // sender address
    to: emailAddress, // list of receivers
    subject: emailData.subject, // Subject line
    html: emailData.message, // html body
  };
   transporter.sendMail(mailBody, (error, info) => {
    if(error){
      console.log(error);
    }else{
      console.log('Email send', + info.response);
    }
  });
  // verify connection configuration
transporter.verify(function (error, success) {
  if (error) {
    console.log(error);
  } else {
    console.log("Server is ready to take our messages");
  }
});
}


// Verify Token Middleware
const verifyToken = async (req, res, next) => {
  const token = req.cookies?.token
  console.log(token)
  if (!token) {
    return res.status(401).send({ message: 'unauthorized access' })
  }
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      console.log(err)
      return res.status(401).send({ message: 'unauthorized access' })
    }
    req.user = decoded
    next()
  })
}
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.g2fbusk.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
})

async function run() {
  try {
    // ============= DATABASE collection =========
    const roomCollection = client.db('stayVista').collection('rooms');
    const userCollection = client.db('stayVista').collection('users');
    const bookingsCollection = client.db('stayVista').collection('bookings');

    // ======= verify admin middleware =====
    const verifyAdmin = async (req, res, next) => {
      const user = req.user;
      const query = {email: user?.email};
      const result = await userCollection.findOne(query);
      if(!result || result?.role !== 'admin') return res.status(401).send({message: 'unAuthorized access!!'})
      next()
    }

    // ======== verify host middleware========
    const verifyHost = async (req, res, next) => {
      const user = req.user;
      const query = {email: user?.email};
      const result = await userCollection.findOne(query);
      if(!result || result?.role !== 'host') return res.status(401).send({message: 'unAuthorized access'})
        next();
    }

    // auth related api ======== jwt==========
    app.post('/jwt', async (req, res) => {
      const user = req.body
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: '365d',
      })
      res
        .cookie('token', token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        })
        .send({ success: true })
    })

    
    // Logout =========== token ======== jwt======
    app.get('/logout', async (req, res) => {
      try {
        res
          .clearCookie('token', {
            maxAge: 0,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
          })
          .send({ success: true })
        console.log('Logout successful')
      } catch (err) {
        res.status(500).send(err)
      }
    })

    // ========= create-payment-intent =========
    app.post('/create-payment-intent', verifyToken, async (req, res) => {
      const price = req.body.price;
      const priceInCent = parseFloat(price) * 100;
      if(!price || priceInCent < 1) return;
      // == generate client secrete paymentIntent===
      const {client_secret} = await stripe.paymentIntents.create({
        amount: priceInCent,
        currency: "usd",
        // In the latest version of the API, specifying the `automatic_payment_methods` parameter is optional because Stripe enables its functionality by default.
        automatic_payment_methods: {
          enabled: true,
        },
      })
      // ==== send client secrete as response ========
      res.send({clientSecret: client_secret});
    })

    // ======= user information save to user DB ====
    app.put('/user', async(req, res) => {
      const user = req.body;
      const query = {email: user?.email};
      // ===== check if user is already exists ===
      const isExist = await userCollection.findOne(query);
      if(isExist){
        if(user?.status === 'Requested'){
          const result = await userCollection.updateOne(query, {$set:{status: user?.status}})
          return res.send(result);
        }else{
          return res.send(isExist)
        }
      }
      // =========== if no user to database run to down code =====
      const options = {upsert: true};
      const updateDoc = {
        $set: {
          ...user,
          timestamp: Date.now()
        }
      }
      const result = await userCollection.updateOne(query, updateDoc, options);
      // send welcome email message ======
      sendEmail(user?.email, {
        subject: "Welcome to StayVista",
        message: "Hope you will find your destination"
      })
      res.send(result);
    })

    // -===== get user info by email from database========
    app.get('/user/:email', async (req, res) => {
      const email = req.params.email
      const result = await userCollection.findOne({ email })
      res.send(result)
    })

    // ======= get all user in database ====
    app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
      const result = await userCollection.find().toArray();
      res.send(result);
    })

    // ====== update a user role ===========
    app.patch('/users/update/:email', async (req, res) => {
      const email = req.params.email;
      const user = req.body;
      const query = {email};
      const updateDoc = {
        $set: {
          ...user,
          timestamp: Date.now()
        }
      }
      const result = await userCollection.updateOne(query, updateDoc);
      res.send(result)
    })


    // ========== rooms collection api ================
    app.get('/rooms', async (req, res) => {
      const category = req.query.category;
      // console.log(category);
      let query = {};
      if(category && category !== 'null') query = {category};
      const result = await roomCollection.find(query).toArray();
      res.send(result);
    })

    app.get('/room/:id', async (req, res) => {
      const id = req.params.id;
      const query = {_id: new ObjectId(id)};
      const result = await roomCollection.findOne(query);
      res.send(result);
    })

    app.post('/room', verifyToken, verifyHost, async (req, res) => {
      const roomData = req.body;
      const result = await roomCollection.insertOne(roomData);
      res.send(result)
    })


    // ========= my listings page rooms data ==========
    app.get('/my-listings/:email', verifyToken, verifyHost, async(req, res) => {
      const email = req.params.email;
      const query = {'host.email': email};
      const result = await roomCollection.find(query).toArray()
      res.send(result);
    })

    // ===== room data item deleted ==========
    app.delete('/room/:id', verifyToken, verifyHost, async (req, res) => {
      const id = req.params.id;
      const query = {_id: new ObjectId(id)};
      const result = await roomCollection.deleteOne(query);
      res.send(result)
    })

    // ======= bookings room save to database --------- 
    app.post('/booking', verifyToken, async (req, res) => {
      const bookingData = req.body;
      // save room booking info
      const result = await bookingsCollection.insertOne(bookingData);
      // send email to guest =======================
      sendEmail(bookingData?.guest?.email, {
        subject: 'Booking Successful!',
        message: `You've Successfully Booked a Room through StayVista. Transaction Id: ${bookingData.transactionId}`
      })

      // send email to host ======================
      sendEmail(bookingData?.host?.email, {
        subject: 'Your Room Got Booked', 
        message: `Get ready to welcome ${bookingData.host.name}`
      })
      // //  == change bookings room status =========
      // const roomId = bookings.roomId;
      // const query = {_id: new ObjectId(roomId)};
      // const updateDoc = {
      //   $set: {booked: true}
      // }
      // const updateRoom = await roomCollection.updateOne(query, updateDoc)
      // console.log('updated room 2231',updateRoom);
      // res.send({result, updateRoom})
      res.send(result)
    })

    // change bookings room status =====
    app.patch('/room/status/:id', async (req, res) => {
      const id = req.params.id;
      const status = req.body.status;
      const query = {_id: new ObjectId(id)};
      const updateDoc = {
        $set: {
          booked: status,
        }
      }
      const result = await roomCollection.updateOne(query, updateDoc)
      res.send(result)
    })

    // update room data in my-listing page with host route
    app.put('/room/update/:id', verifyToken, verifyHost, async (req, res)=> {
      const id = req.params.id;
      const roomData = req.body;
      const query = {_id: new ObjectId(id)};
      const updateDoc = {
        $set: roomData,
      }
      const result = await roomCollection.updateOne(query, updateDoc);
      res.send(result);
    })

    // get all bookings for guest =======
    app.get('/my-bookings/:email', verifyToken,  async(req, res) => {
      const email = req.params.email;
      const query = {'guest.email': email};
      const result = await bookingsCollection.find(query).toArray()
      res.send(result);
    })

    // canceled my bookings user data 
    app.delete('/booking/:id', verifyToken, async (req, res) => {
      const id = req.params.id;
      const query = {_id: new ObjectId(id)}
      const result = await bookingsCollection.deleteOne(query);
      res.send(result)
    })

    // get manage bookings data for host ==
    app.get('/manage-bookings/:email', verifyToken, verifyHost, async (req, res) => {
      const email = req.params.email;
      console.log( 'email = email',email);
      const query = {'host.email': email};
      const result = await bookingsCollection.find(query).toArray();
      res.send(result);
    })

    // Admin statistics ======
    app.get('/admin-stat', verifyToken, verifyAdmin,  async (req, res) => {
      const bookingsDetails = await bookingsCollection.find({}, {projection: {
        date: 1,
        price: 1,
      }}).toArray();
      const totalUsers = await userCollection.countDocuments();
      const totalRooms = await roomCollection.countDocuments();
      const totalPrice =  bookingsDetails.reduce((sum, booking)=> sum + booking.price, 0);

      // const data = [
      //   ['Day', 'Sales'],
      //   ['9', 1000],
      //   ['10', 1170],
      //   ['11', 660],
      //   ['12', 1030],
      // ]
      const chartData = bookingsDetails.map(booking => {
        const day = new Date(booking.date).getDate();
        const month = new Date(booking.date).getMonth() + 1;
        const date = [`${day}/${month}`, booking?.price];
        return date;
      })
      // array added to the chartData two way in js
      chartData.unshift(['Day', 'Sales']);
      //  ===1) ==^^
      // chartData.splice(0,0, ['Day', 'Sales'])
      // == 2) =======^^

      console.log(chartData);
      res.send({
        totalUsers,
        totalRooms, 
        totalBookings: bookingsDetails.length, 
        totalPrice, 
        chartData})
    })

    // Host Statistics ==
    app.get('/host-stat', verifyToken, verifyHost, async(req, res) => {
      const {email} = req.user;
      const bookingsDetails = await bookingsCollection.find(
        {'host.email': email},{
          projection: {
            price: 1,
            date: 1,
          }
        }
      ).toArray();
      const totalRooms = await roomCollection.countDocuments({'host.email': email});
      const totalPrice = bookingsDetails.reduce((sum, booking) => sum + booking.price, 0);
      //  host user logged in date // time stamp 
      const {timestamp} = await userCollection.findOne({email}, {projection: {
        timestamp: 1,
      }})
      // host chart data =
      const chartData = bookingsDetails.map(booking => {
        const day = new Date(booking?.date).getDate();
        const month = new Date(booking?.date).getMonth();
        const date = [`${day}/${month}`, booking?.price];
        return date;
      })
      chartData.unshift(['Day', 'Sales']);
      res.send({
        totalRooms,
        totalPrice,
        hostSince: timestamp,
        totalBookings: bookingsDetails.length, 
        chartData,
      })
    })

    // guest statistics =====
    app.get('/guest-stat', verifyToken, async (req, res) => {
      const {email} = req.user;
      const bookingsDetails = await bookingsCollection.find({'guest.email': email}, {
        projection: {
          price: 1,
          date: 1,
        }
      }).toArray();
      const totalPrice = bookingsDetails.reduce((sum, booking) => sum + booking?.price, 0)
      const {timestamp} = await userCollection.findOne({email}, {projection: {
        timestamp: 1,
      }})
      // host chart data ======
      const chartData = bookingsDetails.map(booking => {
        const day = new Date(booking?.date).getDate();
        const month = new Date(booking?.date).getMonth();
        const date = [`${day}/${month}`, booking?.price];
        return date;
      })
      chartData.unshift(['Day', 'Sales']);
      res.send({
        totalPrice,
        guestSince: timestamp,
        chartData,
        totalBookings: bookingsDetails.length,
      })
    })


    // Send a ping to confirm a successful connection
    await client.db('admin').command({ ping: 1 })
    console.log(
      'Pinged your deployment. You successfully connected to MongoDB!'
    )
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir)

app.get('/', (req, res) => {
  res.send('Hello from StayVista Server..')
})

app.listen(port, () => {
  console.log(`StayVista is running on port ${port}`)
})
