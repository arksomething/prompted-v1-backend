import express from "express";
import cors from "cors";
import jwt from 'jsonwebtoken';
import bodyParser from "body-parser";
import OpenAI from 'openai';
import bcrypt from 'bcrypt';
import postgres from 'pg';
import Stripe from 'stripe';
import 'dotenv/config';

//max tokens dont work

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY)

const { Client } = postgres

const SECRET_KEY = process.env.SECRET_KEY;
const PORT = process.env.BACKEND_PORT;
const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

const client = new Client({
  host: 'localhost',
  user: 'postgres',
  password: process.env.POSTGRES_PASSWORD,
  database: process.env.DB,
  port: 5432,
});

client.connect()
  .then(() => console.log('Connected to PostgreSQL'))
  .catch(err => console.error('Connection error', err.stack));

const authMiddleware = (req, res, next) => {

  const token = req.headers["authorization"].split(" ")[1];
  
  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }
  try {
    // Replace 'your_jwt_secret' with your actual secret key
    const decoded = jwt.verify(token, SECRET_KEY);
    req.id = decoded.id;
    next();
  } catch (ex) {
    return res.status(400).json({ message: 'Invalid token.' });
  }
};

const app = express();
app.use(['/login', '/register', '/user', '/chat', '/playground', '/testing', '/import/choices', '/import/data', '/create-checkout-session'], bodyParser.json());
app.use(cors());
app.use(['/user', '/chat', '/playground', '/testing', '/import/choices', '/create-checkout-session'], authMiddleware)

app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password) {
    return res.status(400).send('Username and password are required');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const defaultPrompts = '[{"id": 1, "name": "Test"}]'
    const result = await client.query('INSERT INTO users (username, password, email, credits, plan, auth, user_prompts) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id', 
      [username, hashedPassword, email, 0, "free", "user", defaultPrompts]);

    res.status(201).send(`User registered with ID: ${result.rows[0].id}`);

  } catch (error) {
    if (error.code === '23505') { // Unique violation
      res.status(409).send('Username already exists');
    } else {
      res.status(500).send('Error registering user');
    }
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Username and password are required');
  }

  try {
    const result = await client.query("SELECT * FROM users WHERE username = $1", [username]);

    if (result.rows.length === 0) {
      return res.status(401).send('Invalid credentials');
    }

    const user = result.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).send('Invalid credentials');
    }

    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).send('Error logging in');
  }
});

app.get('/user', async (req, res) => {

  try {
    const result = await client.query("SELECT * FROM users WHERE id = $1", [req.id]);

    const user = result.rows[0];

    res.json({
      username: user.username,
      email: user.email,
      credits: user.credits,
      plan: user.plan,
      auth: user.auth
    });

  } catch (error) {
    res.status(500).send('Database error');
  }
});

app.post("/chat", async (req, res) => {
  const { chatState, systemPrompt, userPrompt, options } = req.body;
  var newChatState = []

  if (chatState.length == 0) {
    newChatState = [
      {role: "system", content: systemPrompt}, 
      {role: "user", content: userPrompt}
    ]
  } else {
    newChatState = [
      ...chatState, 
      {role: "user", content: userPrompt}
    ]
  }

  const moderation = await openai.moderations.create({input: userPrompt});

  if (moderation.results[0].flagged == true) {
    return res.send("This message was blocked by the ChatGPT Moderation.");
  };

  const completion = await openai.chat.completions.create({
    messages: newChatState,
    model: options.model,
    frequency_penalty: options.frequency,
    presence_penalty: options.presence,
    response_format: options.response,
    temperature: options.temperature,
  });
  
  res.send(completion.choices[0].message.content);
});

app.post("/playground", async (req, res) => {
  const { systemPrompt, engineeringPrompt, userPrompt, options } = req.body;

  var engineeringMessage = '';
  var vanillaMessage = '';

  const moderation = await openai.moderations.create({input: userPrompt});

  if (moderation.results[0].flagged == true) {
    vanillaMessage = "This message was blocked by the ChatGPT Moderation."
  } else {
    const vanilla = await openai.chat.completions.create({
      messages: [
        {role: "system", content: systemPrompt}, 
        {role: "user", content: userPrompt}
      ],
      model: "gpt-3.5-turbo-0125",
      frequency_penalty: options.frequency,
      presence_penalty: options.presence,
      response_format: options.response,
      temperature: options.temperature,
    });

    vanillaMessage = vanilla.choices[0].message.content
  }

  const engModeration = await openai.moderations.create({input: engineeringPrompt.replace("${prompt}", userPrompt)});

  if (engModeration.results[0].flagged == true) {
    engineeringMessage = "This message was blocked by the ChatGPT Moderation."
  } else {
    const engineering = await openai.chat.completions.create({
      messages: [
        {role: "system", content: systemPrompt}, 
        {role: "user", content: engineeringPrompt.replace("${prompt}", userPrompt)}
      ],
      model: "gpt-3.5-turbo-0125",
      frequency_penalty: options.frequency,
      presence_penalty: options.presence,
      response_format: options.response,
      temperature: options.temperature,
    });

    engineeringMessage = engineering.choices[0].message.content
  }

  
  res.send({vanilla: vanillaMessage, engineering: engineeringMessage});
});

app.post("/testing", async (req, res) => {
  const { systemPrompt, engineeringPrompt, userPrompt, index, options} = req.body;

  const moderation = await openai.moderations.create({input: userPrompt});

  if (moderation.results[0].flagged == true) {
    return res.send({index: index, content: "This message was blocked by the ChatGPT Moderation."});
  };

  const completion = await openai.chat.completions.create({
    messages: [
      {role: "system", content: systemPrompt}, 
      {role: "user", content: engineeringPrompt.replace("${prompt}", userPrompt)}
    ],
    model: "gpt-3.5-turbo-0125",
    frequency_penalty: options.frequency,
    presence_penalty: options.presence,
    response_format: options.response,
    temperature: options.temperature,
  });

  const completionMessage = completion.choices[0].message.content

    
  res.send({index: index, content: completionMessage});
});

app.post("/import/choices", async (req, res) => {
  try {
    const result = await client.query("SELECT * FROM users WHERE id = $1", [req.id]);
    const user = result.rows[0];
    res.json(user.user_prompts);

  } catch (error) {
    res.status(500).send('Database error');
  }
})

app.post("/import/data", async (req, res) => {
  try {
    const result = await client.query("SELECT * FROM user_prompts WHERE id = $1", [req.body.id]);
    const userPrompt = result.rows[0];

    res.json({
      name: userPrompt.name,
      prompts: userPrompt.prompts
    });

  } catch (error) {
    res.status(500).send('Database error');
  }
})

app.post('/create-checkout-session', async (req, res) => {

  const session = await stripe.checkout.sessions.create({
    line_items: [
      {
        price_data: {
          currency: 'usd',
          product_data: {
            name: 'Credits',
          },
          unit_amount: 500,
          
        },
        quantity: 1,
      },
    ],
    mode: 'payment',
    metadata: {
      user_id: req.id,
    },
    success_url: process.env.FRONTEND_URL + '/success',
    cancel_url: process.env.FRONTEND_URL + '/cancel',
    
  });

  res.json({url: session.url})
});

async function fulfillCheckout(sessionId, client) {
  console.log('Fulfilling Checkout Session ' + sessionId);

  // Retrieve the Checkout Session from Stripe with line_items expanded
  const checkoutSession = await stripe.checkout.sessions.retrieve(sessionId, {
    expand: ['line_items'],
  });

  // Check if payment was successful and if it requires fulfillment
  if (checkoutSession.payment_status !== 'paid') {
    console.log('Payment not successful or already fulfilled.');
    return;
  }

  try {
    // Start a transaction
    await client.query('BEGIN');

    // Check if the fulfillment has already been performed for this session
    const res = await client.query(
      'SELECT fulfillment_status FROM fulfillments WHERE session_id = $1 FOR UPDATE',
      [sessionId]
    );

    if (res.rows.length > 0 && res.rows[0].fulfillment_status === 'fulfilled') {
      console.log('Fulfillment already performed for this session.');
      await client.query('COMMIT');
      return;
    }

    // Perform fulfillment (update the credits column)
    // Assuming the table has user_id and credits columns, and the user_id is passed in the session's metadata
    const userId = checkoutSession.metadata.user_id; // Ensure you pass user_id in metadata when creating the session
    const creditsToAdd = 500; // Example: Add 10 credits for this session

    await client.query(
      'UPDATE users SET credits = credits + $1 WHERE id = $2',
      [creditsToAdd, userId]
    );

    // Record fulfillment status in the fulfillments table
    await client.query(
      'INSERT INTO fulfillments (session_id, fulfillment_status) VALUES ($1, $2) ON CONFLICT (session_id) DO UPDATE SET fulfillment_status = $2',
      [sessionId, 'fulfilled']
    );

    await client.query('COMMIT');
    console.log('Fulfillment completed successfully.');
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error fulfilling checkout session:', error);
  }
}

app.post('/webhook', bodyParser.raw({type: 'application/json'}), async (request, response) => {
  const payload = request.body;
  const sig = request.headers['stripe-signature'];

  let event;

  try {
    event = stripe.webhooks.constructEvent(payload, sig, endpointSecret);
  } catch (err) {
    console.log(err.message);
    return response.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (
    event.type === 'checkout.session.completed'
    || event.type === 'checkout.session.async_payment_succeeded'
  ) {
    fulfillCheckout(event.data.object.id, client);
  }

  response.status(200).end();
});


// -- Fulfillments Table
// CREATE TABLE fulfillments (
//   session_id TEXT PRIMARY KEY,
//   fulfillment_status TEXT
// );


app.listen(PORT, () => {
  console.log(endpointSecret)
  console.log(`Server is running on port: ${PORT}`);
});


