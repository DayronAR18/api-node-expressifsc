const knex = require('knex')({
 client: 'sqlite3',
 connection: {
 filename: './meubanco.db'
 },
 useNullAsDefault: true
});
module.exports = knex;