// =====================================================
//  OAuth2 Callback Server — Railway Deployment
//  Recebe o código do Discord, troca pelo token e
//  salva no MariaDB da VPS
// =====================================================

require('dotenv').config();
const express = require('express');
const axios = require('axios');
const mariadb = require('mariadb');

const app = express();
const PORT = process.env.PORT || 3000;

// Pool do banco de dados (Railway MySQL — variáveis injetadas automaticamente)
const dbPool = mariadb.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: parseInt(process.env.MYSQLPORT || '3306'),
  connectionLimit: 3,
});

// Garante que a tabela existe
async function initDatabase() {
  let conn;
  try {
    conn = await dbPool.getConnection();
    await conn.query(`
      CREATE TABLE IF NOT EXISTS Tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id VARCHAR(32) NOT NULL UNIQUE,
        access_token TEXT NOT NULL,
        refresh_token TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);
    console.log('✅ Tabela Tokens ok');
  } catch (err) {
    console.error('❌ Erro ao conectar no banco:', err.message);
  } finally {
    if (conn) conn.release();
  }
}

initDatabase();

// ── Rota de Callback ─────────────────────────────────

app.get('/callback', async (req, res) => {
  const code = req.query.code;

  if (!code) return res.status(400).send('Código ausente.');

  const redirectUri = process.env.REDIRECT_URI;
  const clientId = process.env.CLIENT_ID;
  const clientSecret = process.env.CLIENT_SECRET;

  if (!redirectUri || !clientId || !clientSecret) {
    return res.status(500).send('Variáveis de ambiente não configuradas.');
  }

  try {
    // Troca o código pelo token
    const params = new URLSearchParams();
    params.append('client_id', clientId);
    params.append('client_secret', clientSecret);
    params.append('grant_type', 'authorization_code');
    params.append('code', code);
    params.append('redirect_uri', redirectUri);

    const tokenResponse = await axios.post('https://discord.com/api/oauth2/token', params, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });

    const accessToken = tokenResponse.data.access_token;
    const refreshToken = tokenResponse.data.refresh_token;

    // Descobre o ID do usuário
    const userResponse = await axios.get('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    const discordUserId = userResponse.data.id;

    // Salva no banco
    let conn;
    try {
      conn = await dbPool.getConnection();
      await conn.query(
        `INSERT INTO Tokens (user_id, access_token, refresh_token)
         VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE access_token = VALUES(access_token), refresh_token = VALUES(refresh_token)`,
        [discordUserId, accessToken, refreshToken || '']
      );
      console.log(`✅ Token salvo para user ${discordUserId}`);
    } finally {
      if (conn) conn.release();
    }

    res.send(`
      <html>
        <body style="font-family: sans-serif; text-align: center; padding: 60px; background: #2f3136; color: white;">
          <h2>✅ Autorizado!</h2>
          <p>Você já pode voltar pro Discord e clicar em <strong>"Já autorizei, continuar"</strong>.</p>
        </body>
      </html>
    `);
  } catch (error) {
    console.error('❌ Erro callback:', error.response?.data || error.message);
    res.status(500).send('Erro ao autorizar. Tente novamente.');
  }
});

app.get('/', (req, res) => res.send('Bot callback online!'));

// Endpoint para o bot na VPS verificar se o token existe
app.get('/check', async (req, res) => {
  const userId = req.query.user_id;
  if (!userId) return res.json({ hasToken: false });

  let conn;
  try {
    conn = await dbPool.getConnection();
    const rows = await conn.query('SELECT id FROM Tokens WHERE user_id = ? LIMIT 1', [userId]);
    res.json({ hasToken: rows.length > 0 });
  } catch {
    res.json({ hasToken: false });
  } finally {
    if (conn) conn.release();
  }
});

app.listen(PORT, () => console.log(`🌐 Servidor rodando na porta ${PORT}`));
