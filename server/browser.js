function encode(arraybuffer) {
  let s = String.fromCharCode.apply(null, new Uint8Array(arraybuffer))
  return window.btoa(s).replace(/\+/g,'-').replace(/\//g, '_')
}

function decode(str) {
  let s = window.atob(str.replace(/-/g, '+').replace(/_/g, '/'))
  let bytes = Uint8Array.from(s, c=>c.charCodeAt(0))
  return bytes.buffer
}

let options = {"rp":{"name":"Ryan O'Laughlin's website","id":"ryanjolaughlin.com"},"user":{"name":"testuser1","id":"NjM3YWQ5YTk2OTMwNjNjMDMxMGNhMGRm","displayName":"testuser1"},"challenge":"zwwP5Cwj7QMNVx6J6xCNOGC9Z3A35GfOg7ZxoiUaCbndNacN3QugqvLjRkbUAZ798SN7LQLSEDnHY-guOcaXPg","pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257}],"timeout":30000,"authenticatorSelection":{"authenticatorAttachment":"cross-platform","residentKey":"preferred","userVerification":"required"},"attestation":"none"}

options.challenge = decode(options.challenge)
options.user.id = decode(options.user.id)

let response 
response = await navigator.credentials.create({ publicKey: options })

let out = {
  id: response.id,
  rawId: encode(response.rawId),
  response: {
    attestationObject: encode(response.response.attestationObject),
    clientDataJSON: encode(response.response.clientDataJSON)
  },
  type: response.type
}


function encode(arraybuffer) {
  let s = String.fromCharCode.apply(null, new Uint8Array(arraybuffer))
  return window.btoa(s).replace(/\+/g,'-').replace(/\//g, '_')
}

function decode(str) {
  let s = window.atob(str.replace(/-/g, '+').replace(/_/g, '/'))
  let bytes = Uint8Array.from(s, c=>c.charCodeAt(0))
  return bytes.buffer
}

let options = {"challenge":"zg9NTuV_cJ-nzXtd2jsPkaApzoMkVuxvFDrzJwCoZypbLC3uLoDTz-pWgKyyY7bW9VaQmYxLoBa1pH6H6afyhg","timeout":30000,"rpId":"ryanjolaughlin.com","userVerification":"required"}
options.challenge = decode(options.challenge)

let response 
response = await navigator.credentials.get({ publicKey: options })

let out = {
  id: response.id,
  rawId: encode(response.rawId),
  response: {
    authenticatorData: encode(response.response.authenticatorData),
    clientDataJSON: encode(response.response.clientDataJSON),
    signature: encode(response.response.signature),
    userHandle: encode(response.response.userHandle)
  },
  type: response.type
}