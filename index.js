// =====================================================
//  OAuth2 Callback Server — Railway Deployment
//  Recebe o código do Discord, troca pelo token e
//  salva no MariaDB da VPS
// =====================================================

require('dotenv').config();
const express = require('express');
const axios = require('axios');
const mariadb = require('mariadb');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Pool do banco de dados (Railway MySQL — variáveis injetadas automaticamente)
const hasDbConfig = !!(
  process.env.MYSQLHOST &&
  process.env.MYSQLUSER &&
  process.env.MYSQLPASSWORD &&
  process.env.MYSQLDATABASE
);

let dbPool = null;
if (hasDbConfig) {
  dbPool = mariadb.createPool({
    host: process.env.MYSQLHOST,
    user: process.env.MYSQLUSER,
    password: process.env.MYSQLPASSWORD,
    database: process.env.MYSQLDATABASE,
    port: parseInt(process.env.MYSQLPORT || '3306'),
    connectionLimit: 3,
    acquireTimeout: 10000, // ms waiting for a free connection from pool
    connectTimeout: 10000, // ms timeout for TCP connect
  });
} else {
  console.warn('⚠️  DB config missing — skipping DB pool creation. Set MYSQLHOST/USER/PASSWORD/DATABASE to enable DB.');
}

// Garante que a tabela existe
async function initDatabase() {
  if (!dbPool) return;
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
    console.error('❌ Erro ao inicializar tabela Tokens:', err && err.stack ? err.stack : err);
    // Se a tentativa de obter conexão falhar repetidamente, desabilitar o pool
    try {
      if (dbPool && typeof dbPool.end === 'function') {
        await dbPool.end();
        console.warn('⚠️  DB pool encerrado devido a falha de conexão. Desabilitando persistência.');
      }
    } catch (endErr) {
      console.warn('⚠️  Falha ao encerrar DB pool:', endErr && endErr.message ? endErr.message : endErr);
    }
    dbPool = null;
  } finally {
    if (conn) try { conn.release(); } catch (e) { /* ignore */ }
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

    // Salva no banco (se configurado)
    if (dbPool) {
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
      } catch (err) {
        console.error('❌ Erro ao salvar token no DB:', err && err.stack ? err.stack : err);
      } finally {
        if (conn) try { conn.release(); } catch (e) { /* ignore */ }
      }
    } else {
      console.warn('⚠️  DB não configurado — token não foi persistido.');
      // Fallback opcional: persiste em arquivo local se habilitado
      try {
        const useFile = process.env.FILE_FALLBACK === 'true';
        if (useFile) {
          const record = {
            created_at: new Date().toISOString(),
            user_id: discordUserId,
            access_token: accessToken,
            refresh_token: refreshToken || null,
          };
          fs.appendFileSync('tokens.log', JSON.stringify(record) + '\n', { encoding: 'utf8' });
          console.log('✅ Token registrado em tokens.log (fallback de arquivo)');
        }
      } catch (fileErr) {
        console.warn('⚠️  Falha ao escrever arquivo de fallback:', fileErr && fileErr.message ? fileErr.message : fileErr);
      }
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
    const debug = process.env.DEBUG === 'true';
    const errData = error.response?.data || error.message || error;
    console.error('❌ Erro callback:', errData);
    if (debug) {
      // Em modo debug, devolver detalhes para facilitar diagnóstico localmente
      return res.status(500).send(`Erro ao autorizar: ${JSON.stringify(errData)}`);
    }
    // Mensagem amigável e instrução para re-tentar fluxo OAuth
    if (error.response && error.response.data && error.response.data.error === 'invalid_grant') {
      return res.status(400).send('Código inválido ou expirado. Reinicie o fluxo de autorização e tente novamente.');
    }
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
