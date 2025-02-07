// server.js
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const JWT_SECRET = 'your_secret_key'; // Käytä tuotannossa ympäristömuuttujaa

// Yhdistetään MongoDB:hen (oletetaan, että MongoDB on käynnissä paikallisesti)
mongoose.connect('mongodb://localhost/tuotanto', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error(err));

// Määritellään Mongoose-mallit

// Käyttäjämalli
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  name: String
});
const User = mongoose.model('User', userSchema);

// Projektimalli
const projectSchema = new mongoose.Schema({
  name: String,
  startDate: Date,
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  sharedWith: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});
const Project = mongoose.model('Project', projectSchema);

// Tehtävämalli
const taskSchema = new mongoose.Schema({
  projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
  name: String,
  startDate: Date,
  estimatedHours: Number,
  taskNumber: Number,
  actualHours: Number,
  completion: Number,
  dailyHours: Number
});
const Task = mongoose.model('Task', taskSchema);

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// JWT-autentikointimiddleware
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });
  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
}

// Rekisteröinti
app.post('/api/register', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name)
    return res.status(400).json({ error: 'Email, password and name are required' });
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword, name });
    await user.save();
    res.json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Error registering user', details: err });
  }
});

// Kirjautuminen
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required' });
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Error logging in', details: err });
  }
});

// Projektien endpointit (vain niihin, joihin käyttäjällä on pääsy: omistaja tai jaettu)
app.get('/api/projects', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    const projects = await Project.find({ $or: [ { owner: userId }, { sharedWith: userId } ] });
    res.json(projects);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching projects' });
  }
});

app.get('/api/projects/:projectId', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    const project = await Project.findOne({
      _id: req.params.projectId,
      $or: [ { owner: userId }, { sharedWith: userId } ]
    });
    if (!project) return res.status(404).json({ error: 'Project not found or access denied' });
    res.json(project);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching project' });
  }
});

app.post('/api/projects', authenticate, async (req, res) => {
  const { name, startDate } = req.body;
  if (!name || !startDate)
    return res.status(400).json({ error: 'Name and startDate are required' });
  try {
    const project = new Project({ name, startDate, owner: req.user.id, sharedWith: [] });
    await project.save();
    res.json(project);
  } catch (err) {
    res.status(500).json({ error: 'Error creating project' });
  }
});

app.delete('/api/projects/:projectId', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    const project = await Project.findOne({ _id: req.params.projectId, owner: userId });
    if (!project) return res.status(404).json({ error: 'Project not found or access denied' });
    await Project.deleteOne({ _id: req.params.projectId });
    await Task.deleteMany({ projectId: req.params.projectId });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Error deleting project' });
  }
});

// Projektin jakaminen toiselle käyttäjälle (vain omistajalla)
app.post('/api/projects/:projectId/share', authenticate, async (req, res) => {
  const { email } = req.body; // Jaettavan käyttäjän sähköposti
  if (!email) return res.status(400).json({ error: 'Email is required' });
  try {
    const userToShare = await User.findOne({ email });
    if (!userToShare) return res.status(404).json({ error: 'User not found' });
    const project = await Project.findOne({ _id: req.params.projectId, owner: req.user.id });
    if (!project) return res.status(404).json({ error: 'Project not found or access denied' });
    if (!project.sharedWith.includes(userToShare._id)) {
      project.sharedWith.push(userToShare._id);
      await project.save();
    }
    res.json({ message: 'Project shared successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Error sharing project', details: err });
  }
});

// Tehtävien endpointit (vain niihin, joihin käyttäjällä on pääsy projektiin)
app.get('/api/projects/:projectId/tasks', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    const project = await Project.findOne({
      _id: req.params.projectId,
      $or: [ { owner: userId }, { sharedWith: userId } ]
    });
    if (!project) return res.status(404).json({ error: 'Project not found or access denied' });
    const tasks = await Task.find({ projectId: req.params.projectId });
    res.json(tasks);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching tasks' });
  }
});

app.post('/api/projects/:projectId/tasks', authenticate, async (req, res) => {
  const { name, startDate, estimatedHours, taskNumber, dailyHours } = req.body;
  if (!name || !startDate || !estimatedHours || !taskNumber)
    return res.status(400).json({ error: 'All fields are required' });
  try {
    const userId = req.user.id;
    const project = await Project.findOne({
      _id: req.params.projectId,
      $or: [ { owner: userId }, { sharedWith: userId } ]
    });
    if (!project) return res.status(404).json({ error: 'Project not found or access denied' });
    const resource = ([8, 16, 24].includes(Number(dailyHours)) ? Number(dailyHours) : 8);
    const task = new Task({
      projectId: req.params.projectId,
      name,
      startDate,
      estimatedHours: Number(estimatedHours),
      taskNumber: Number(taskNumber),
      actualHours: 0,
      completion: 0,
      dailyHours: resource
    });
    await task.save();
    res.json(task);
  } catch (err) {
    res.status(500).json({ error: 'Error creating task', details: err });
  }
});

app.put('/api/projects/:projectId/tasks/:taskId', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    const project = await Project.findOne({
      _id: req.params.projectId,
      $or: [ { owner: userId }, { sharedWith: userId } ]
    });
    if (!project) return res.status(404).json({ error: 'Project not found or access denied' });
    const task = await Task.findOne({ _id: req.params.taskId, projectId: req.params.projectId });
    if (!task) return res.status(404).json({ error: 'Task not found' });
    const { actualHours, completion, dailyHours } = req.body;
    if (actualHours !== undefined) task.actualHours = Number(actualHours);
    if (completion !== undefined) task.completion = Number(completion);
    if (dailyHours !== undefined)
      task.dailyHours = ([8, 16, 24].includes(Number(dailyHours)) ? Number(dailyHours) : 8);
    await task.save();
    res.json(task);
  } catch (err) {
    res.status(500).json({ error: 'Error updating task' });
  }
});

app.delete('/api/projects/:projectId/tasks/:taskId', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    const project = await Project.findOne({
      _id: req.params.projectId,
      $or: [ { owner: userId }, { sharedWith: userId } ]
    });
    if (!project) return res.status(404).json({ error: 'Project not found or access denied' });
    await Task.deleteOne({ _id: req.params.taskId, projectId: req.params.projectId });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Error deleting task' });
  }
});

// Käynnistetään palvelin
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Palvelin käynnissä portissa ${PORT}`);
});
