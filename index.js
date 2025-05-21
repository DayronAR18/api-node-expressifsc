const express = require('express');
const knex = require('./db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
app.use(express.json());

const SEGREDO = "minhasecretkey";

// Criação das tabelas
async function criarTabelas() {
  const existeUsuarios = await knex.schema.hasTable('usuarios');
  if (!existeUsuarios) {
    await knex.schema.createTable('usuarios', table => {
      table.increments('id');
      table.string('nome');
      table.string('email').unique();
      table.string('senha');
    });
  }
  const existeMensagens = await knex.schema.hasTable('mensagens');
  if (!existeMensagens) {
    await knex.schema.createTable('mensagens', table => {
      table.increments('id');
      table.integer('usuario_id').references('id').inTable('usuarios');
      table.text('texto');
      table.timestamp('data_postagem').defaultTo(knex.fn.now());
    });
  }
}
criarTabelas();

// Rotas de inscrição e login
app.post('/signup', async (req, res) => {
  const { nome, email, senha } = req.body;
  const hash = await bcrypt.hash(senha, 10);
  await knex('usuarios').insert({ nome, email, senha: hash });
  res.status(201).json({ mensagem: "Usuário cadastrado!" });
});

app.post('/login', async (req, res) => {
  const { email, senha } = req.body;
  const usuario = await knex('usuarios').where({ email }).first();
  if (!usuario || !(await bcrypt.compare(senha, usuario.senha))) {
    return res.status(401).json({ erro: "Credenciais inválidas" });
  }
  const token = jwt.sign({ id: usuario.id }, SEGREDO);
  res.json({ token });
});

// Middleware de autenticação
function autenticar(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ erro: "Token não enviado" });
  try {
    const [, token] = auth.split(" ");
    const payload = jwt.verify(token, SEGREDO);
    req.usuario_id = payload.id;
    next();
  } catch {
    res.status(401).json({ erro: "Token inválido" });
  }
}

// Rotas protegidas e abertas
app.post('/mensagens', autenticar, async (req, res) => {
  const { texto } = req.body;
  await knex('mensagens').insert({
    usuario_id: req.usuario_id,
    texto
  });
  res.status(201).json({ mensagem: "Mensagem criada" });
});

app.get('/usuarios', async (req, res) => {
  try {
    const usuarios = await knex('usuarios').select('*');
    res.json(usuarios);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar usuários' });
  }
});

app.get('/mensagens', async (req, res) => {
  const mensagens = await knex('mensagens')
    .join('usuarios', 'usuarios.id', '=', 'mensagens.usuario_id')
    .select('mensagens.id', 'usuarios.nome', 'mensagens.texto', 'mensagens.data_postagem');
  res.json(mensagens);
});
// verificar se as tabelas foram criadas corretamente
knex.raw("SELECT name FROM sqlite_master WHERE type='table';")
  .then((tables) => {
    console.log('Tabelas existentes:', tables);
  })
  .catch((error) => {
    console.error('Erro ao listar tabelas:', error);
  });

app.listen(3000, () => {
  console.log('Servidor rodando em http://localhost:3000');
});