import express from "express";
import cors from "cors";
import jwt from 'jsonwebtoken';
import bodyParser from "body-parser";
import OpenAI from 'openai';
import bcrypt from 'bcrypt';
import postgres from 'pg';
import 'dotenv/config';

//max tokens dont work

const { Client } = postgres

const SECRET_KEY = process.env.SECRET_KEY;
const PORT = process.env.PORT;

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

const client = new Client({
  host: 'localhost',
  user: 'postgres',
  password: process.env.POSTGRES_PASSWORD,
  database: 'authdb',
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
app.use(bodyParser.json());
app.use(cors());
app.use(['/user', '/chat', '/playground', '/testing', '/import/choices'], authMiddleware)

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

  const vanillaMessage = vanilla.choices[0].message.content
  const engineeringMessage = engineering.choices[0].message.content
  
  res.send({vanilla: vanillaMessage, engineering: engineeringMessage});
});

app.post("/testing", async (req, res) => {
  const { systemPrompt, engineeringPrompt, userPrompt, index, options} = req.body;

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

    console.log(userPrompt)
    res.json({
      name: userPrompt.name,
      prompts: userPrompt.prompts
    });

  } catch (error) {
    res.status(500).send('Database error');
  }
})

app.listen(PORT, () => {
  console.log(`Server is running on port: ${PORT}`);
});
