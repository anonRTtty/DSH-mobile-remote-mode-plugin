// Two-process multicast probe: receiver binds 48765 + joins group,
// sender (separate process) sends to the group. Verifies cross-process
// multicast delivery (the one thing the in-process probe could not test).
// argv[2] === 'send' -> sender, otherwise receiver.
import dgram from 'node:dgram'

const GROUP = '239.255.76.65'
const PORT = 48765
const mode = process.argv[2]

if (mode === 'send') {
  const s = dgram.createSocket({ type: 'udp4', reuseAddr: true })
  s.bind(PORT, '0.0.0.0', () => {
    s.setMulticastTTL(1)
    s.setMulticastLoopback(true)
    setTimeout(() => {
      s.send(Buffer.from('multicast-cross-process'), PORT, GROUP, (err) => {
        console.log('[send] sent, err=', err ? err.message : 'none')
        setTimeout(() => process.exit(0), 1500)
      })
    }, 500)
  })
} else {
  const s = dgram.createSocket({ type: 'udp4', reuseAddr: true })
  s.on('message', (msg, rinfo) => console.log('[recv] GOT', msg.toString(), 'from', rinfo.address))
  s.on('error', (e) => console.log('[recv] error', e.code, e.message))
  s.bind(PORT, '0.0.0.0', () => {
    try {
      s.setMulticastTTL(1)
      s.setMulticastLoopback(true)
      s.addMembership(GROUP)
      console.log('[recv] bound + joined')
    } catch (e) {
      console.log('[recv] membership error', e.message)
    }
  })
  setTimeout(() => {
    console.log('[recv] done (5s)')
    process.exit(0)
  }, 5000)
}
