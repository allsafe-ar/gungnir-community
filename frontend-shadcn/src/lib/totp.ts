const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function bytesToBase32(bytes: Uint8Array): string {
  let bits = 0, value = 0, out = ''
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31]
  return out
}

function base32ToBytes(s: string): Uint8Array {
  const clean = s.toUpperCase().replace(/=+$/, '')
  let bits = 0, value = 0
  const out: number[] = []
  for (const c of clean) {
    const idx = B32.indexOf(c)
    if (idx < 0) continue
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8 }
  }
  return new Uint8Array(out)
}

function hotpSync(secret: string, counter: number): string {
  const key = base32ToBytes(secret)
  const buf = new ArrayBuffer(8)
  const view = new DataView(buf)
  view.setUint32(4, counter >>> 0, false)
  const msg = new Uint8Array(buf)

  // HMAC-SHA1 (sync, browser SubtleCrypto is async — using pure-JS fallback)
  // Simple pure-JS SHA-1 HMAC for TOTP (RFC 4226)
  function sha1(data: number[]): number[] {
    let h0=0x67452301,h1=0xEFCDAB89,h2=0x98BADCFE,h3=0x10325476,h4=0xC3D2E1F0
    const msg2=[...data]
    const bitLen=data.length*8
    msg2.push(0x80)
    while(msg2.length%64!==56)msg2.push(0)
    for(let i=7;i>=0;i--)msg2.push((bitLen/(Math.pow(2,i*8)))&0xff)
    for(let i=0;i<msg2.length;i+=64){
      const w:number[]=[]
      for(let j=0;j<16;j++)w[j]=(msg2[i+j*4]<<24)|(msg2[i+j*4+1]<<16)|(msg2[i+j*4+2]<<8)|msg2[i+j*4+3]
      for(let j=16;j<80;j++){const x=w[j-3]^w[j-8]^w[j-14]^w[j-16];w[j]=(x<<1)|(x>>>31)}
      let a=h0,b=h1,c=h2,d=h3,e=h4
      for(let j=0;j<80;j++){
        let f=0,k=0
        if(j<20){f=(b&c)|((~b)&d);k=0x5A827999}
        else if(j<40){f=b^c^d;k=0x6ED9EBA1}
        else if(j<60){f=(b&c)|(b&d)|(c&d);k=0x8F1BBCDC}
        else{f=b^c^d;k=0xCA62C1D6}
        const tmp=(((a<<5)|(a>>>27))+f+e+k+w[j])>>>0
        e=d;d=c;c=(b<<30)|(b>>>2);b=a;a=tmp
      }
      h0=(h0+a)>>>0;h1=(h1+b)>>>0;h2=(h2+c)>>>0;h3=(h3+d)>>>0;h4=(h4+e)>>>0
    }
    const res:number[]=[]
    for(const h of[h0,h1,h2,h3,h4])for(let i=3;i>=0;i--)res.push((h>>>(i*8))&0xff)
    return res
  }

  const blockSize = 64
  let k = Array.from(key)
  if (k.length > blockSize) k = sha1(k)
  while (k.length < blockSize) k.push(0)
  const ipad = k.map(b => b ^ 0x36)
  const opad = k.map(b => b ^ 0x5c)
  const inner = sha1([...ipad, ...Array.from(msg)])
  const hmac = sha1([...opad, ...inner])

  const offset = hmac[19] & 0xf
  const code = ((hmac[offset] & 0x7f) << 24) | (hmac[offset+1] << 16) | (hmac[offset+2] << 8) | hmac[offset+3]
  return String(code % 1000000).padStart(6, '0')
}

export function generateTOTPSecret(): string {
  return bytesToBase32(crypto.getRandomValues(new Uint8Array(20)))
}

export function verifyTOTP(secret: string, token: string): boolean {
  const t = String(token).replace(/\s/g, '')
  const counter = Math.floor(Date.now() / 1000 / 30)
  for (let delta = -5; delta <= 5; delta++) {
    if (hotpSync(secret, counter + delta) === t) return true
  }
  return false
}

export function totpQRUrl(secret: string, username: string): string {
  const uri = `otpauth://totp/AllSafe%20ARP:${encodeURIComponent(username)}?secret=${secret}&issuer=AllSafe%20ARP&algorithm=SHA1&digits=6&period=30`
  return `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(uri)}`
}
