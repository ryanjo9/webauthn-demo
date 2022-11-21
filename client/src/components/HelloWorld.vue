<template>
  <div class="hello">

    <div class="register" v-if="view === 'register'">
      <p>
        To get started, enter a username and click the register button. Your browser will let you choose to register a passkey on this device or on another compatible device.
      </p>
      <p>
        Keep in mind, even though your device may ask for biometric authentication, your biometric data <b>never leaves your device</b>. Even if I wanted to access your biometric data, it is impossible
        to access that data through passkeys and webauthn :)
      </p>

      <input style="max-width:200px;margin:auto" type="text" class="form-control field-value" v-model="username" placeholder="username">

      <button style="margin-top:8px;margin:auto;margin-bottom:8px;" type="button" class="btn btn-success" @click="registerKey">Register</button>
    </div>
    <div class="login" v-if="view === 'login'">
      <p>
        To login with a passkey, click the login button. You'll be asked to choose a passkey from this device or use a passkey from a different device.
        Logging in with passkeys removes the need for passwords you don't even need to type in your username! 
      </p> 
      <p>
        Keep in mind, even though your device may ask for biometric authentication, your biometric data <b>never leaves your device</b>. Even if I wanted to access your biometric data, it is impossible
        to access that data through passkeys and webauthn :) 
      </p>
      <button type="button" class="btn btn-success" @click="validateKey">Login</button>
      <p v-if="loggedInUsername !== ''">Logged in as {{ loggedInUsername }}</p>
    </div>

    <div v-if="view === 'login'">
      <p>Don't have a passkey for this site or want to register a new passkey?</p>
      <button v-if="view === 'login'" type="button" class="btn btn-success" @click="setView('register')">Try Registration</button>
    </div>
    
    <div v-if="view === 'register'">
      <p>Once you've registered a passkey, try logging in with it!</p>
      <button v-if="view === 'register'" style="margin-left:8px" type="button" class="btn btn-success" @click="setView('login')">Try Logging In</button>
    </div>

    <a href="https://github.com/ryanjo9/webauthn-demo">View the source code</a>
  </div>
</template>

<script>
import axios from 'axios'

function encode(arraybuffer) {
  let s = String.fromCharCode.apply(null, new Uint8Array(arraybuffer))
  return window.btoa(s).replace(/\+/g,'-').replace(/\//g, '_')
}

function decode(str) {
  let s = window.atob(str.replace(/-/g, '+').replace(/_/g, '/'))
  let bytes = Uint8Array.from(s, c=>c.charCodeAt(0))
  return bytes.buffer
}

export default {
  name: 'HelloWorld',
  props: {
    msg: String
  },
  data() {
    return {
      username: '',
      loggedInUsername: '',
      view: 'register'
    }
  },
  methods: {
    async validateKey() {
      try {
        const { data: options } = await axios.post('/api/generate-challenge', {purpose: 'authentication'})
      
        options.challenge = decode(options.challenge)

        let key = await navigator.credentials.get({ publicKey: options })

        let validateReq = {
          id: key.id,
          rawId: encode(key.rawId),
          response: {
            authenticatorData: encode(key.response.authenticatorData),
            clientDataJSON: encode(key.response.clientDataJSON),
            signature: encode(key.response.signature),
            userHandle: encode(key.response.userHandle)
          },
          type: key.type
        }

        await axios.post('/api/validate-key', validateReq)
      } catch (error) {
        console.log(error)
      }
    },
    async registerKey() {
      try {
        const { data: options } = await axios.post('/api/generate-challenge', {purpose: 'registration', username: this.username})
      
        options.challenge = decode(options.challenge)
        options.user.id = decode(options.user.id)

        let key = await navigator.credentials.create({ publicKey: options })

        let registerReq = {
          id: key.id,
          rawId: encode(key.rawId),
          response: {
            attestationObject: encode(key.response.attestationObject),
            clientDataJSON: encode(key.response.clientDataJSON)
          },
          type: key.type
        }

        await axios.post('/api/register-key', registerReq)
        this.username = ''
      } catch (error) {
        console.log(error)
      }
    },
    setView(view) {
      this.view = view
    }
  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
h3 {
  margin: 40px 0 0;
}
ul {
  list-style-type: none;
  padding: 0;
}
li {
  display: inline-block;
  margin: 0 10px;
}
a {
  color: #42b983;
}

.register {
  margin: auto;
  max-width: 700px;
  margin-top: 20px;
}

.login {
  max-width: 700px;
  margin: auto;
  margin-top: 16px;
  margin-bottom: 20px;
}
</style>
