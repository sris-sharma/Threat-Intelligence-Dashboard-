const localtunnel = require('localtunnel');

async function startTunnel() {
  try {
    const tunnel = await localtunnel({ port: 3000 });
    console.log('PUBLIC_TUNNEL_URL=' + tunnel.url);

    tunnel.on('close', () => {
      console.log('Tunnel closed, attempting reconnect in 5s...');
      setTimeout(startTunnel, 5000);
    });

    tunnel.on('error', (err) => {
      console.error('Tunnel error:', err);
    });
  } catch (err) {
    console.error('Failed to create tunnel:', err);
    setTimeout(startTunnel, 5000);
  }
}

startTunnel();
