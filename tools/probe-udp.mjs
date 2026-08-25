// Probe: multicast loopback + reuseAddr on Windows.
// Two sockets bound to the same port with reuseAddr, both members of the group.
// One sends to the group; we check whether BOTH sockets receive the packet.
import dgram from 'node:dgram'

const GROUP = '239.255.76.65'
const PORT = 48765

function makeSocket(label) {
  const s = dgram.createSocket({ type: 'udp4', reuseAddr: true })
  const got = []
  s.on('message', (msg, rinfo) => {
    got.push(msg.toString())
    console.log(`[${label}] received from ${rinfo.address}:${rinfo.port}: ${msg}`)
  })
  s.on('error', (e) => console.log(`[${label}] error: ${e.code} ${e.message}`))
  s.bind(PORT, '0.0.0.0', () => {
    try {
      s.setMulticastTTL(1)
      s.setMulticastLoopback(true)
      s.addMembership(GROUP)
      // membership on loopback + default
      try { s.addMembership(GROUP, '127.0.0.1') } catch (e) { console.log(`[${label}] membership lo err: ${e.message}`) }
      console.log(`[${label}] bound ${PORT}, joined ${GROUP}`)
    } catch (e) {
      console.log(`[${label}] setup error: ${e.message}`)
    }
  })
  return { s, got }
}

const a = makeSocket('A')
const b = makeSocket('B')

setTimeout(() => {
  const payload = Buffer.from('hello-from-A')
  console.log('A sending to group...')
  a.s.send(payload, PORT, GROUP, (err) => {
    if (err) console.log('A send err:', err.message)
  })
  // also send a loopback unicast
  a.s.send(Buffer.from('unicast-from-A'), PORT, '127.0.0.1', (err) => {
    if (err) console.log('A unicast err:', err.message)
  })
}, 800)

setTimeout(() => {
  console.log('=== A received:', JSON.stringify(a.got))
  console.log('=== B received:', JSON.stringify(b.got))
  a.s.close()
  b.s.close()
  process.exit(0)
}, 2000)
