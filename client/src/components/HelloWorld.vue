<template>
  <div class="hello">
    <div class="intro">
      <p>
        Passkeys are a new type of credential built on the WebAuthN spec that are easier to use and more secure than passwords.
        Instead of asking you creating, remembering, and reusing a password, websites and apps can ask your device to generate a passkey.
      </p>
      <p>
        Passkeys are a new technology so they're not supported on all devices and browsers yet. This demo works best in Safari on a Mac running macOS Ventura and with iPhone running iOS 16. 
        Better passkey experiences are coming soon for Android, Windows, and Chrome on Mac.
      </p>
    </div>
    <div class="register" v-if="view === 'register'">
      <p>
        To get started, enter a username then click the register button. Follow the prompts that pop up to save a passkey.
      </p>
      <p>
        Keep in mind, even though your device may ask for FaceId or your fingerprint, your biometric data <b>never leaves your device</b>. Your device only reveals whether or not it verified your identity and a signature of your passkey.
      </p>

      <div class="demo-action">
        <p>Create a new passkey</p>
        <input style="max-width:200px;margin:auto;margin-bottom:8px;margin-top:8px;" type="text" class="form-control field-value" v-model="username" placeholder="username">
        
        <p>Letters or numbers (a-z,0-9): {{ getValidationEmoji(hasValidChars) }}</p>
        <p>Between 4-16 characters: {{ getValidationEmoji(isValidLength) }}</p>

        <button :disabled="isRegisterDisabled" style="margin:auto;margin-top:8px;" type="button" class="btn btn-success" @click="registerKey">Register</button>

        <p v-if="errorMsg" style="color: red">{{ errorMsg }}</p>
      </div>
    </div>
    <div class="login" v-if="view === 'login'">
      <p>
        With passkeys, you don't even need to type in your username. Simply click on "Login" and follow the prompts to choose the account you want to sign in to.
        Logging in with a passkey provides two factors of authentication: 1) Something you have (the passkey on your device) and 2) Something you are or something you know (FaceId, TouchId, device password or device passcode).
      </p>
      <div class="demo-action">
        <p>Login with a passkey</p>
        <button style="margin-bottom:8px;" type="button" class="btn btn-success" @click="validateKey">Login</button>
        <p v-if="loggedInUsername !== ''" style="margin-bottom:0px;">You logged in as {{ loggedInUsername }}</p>
        <p v-if="errorMsg" style="color: red;margin-bottom:0px;">{{ errorMsg }}</p>
      </div>
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
      view: 'register',
      errorMsg: '',
      validLength: false,
      validChars: false
    }
  },
  computed: {
    isValidLength() {
      return this.username.length <= 16 && this.username.length >= 4
    },
    hasValidChars() {
      const reg = /[^a-zA-Z0-9]+/ // only letters and numbers
      return !reg.test(this.username)
    },
    isRegisterDisabled() {
      return !(this.isValidLength && this.hasValidChars)
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

        const { data } = await axios.post('/api/validate-key', validateReq)

        this.loggedInUsername = data.username
        this.errorMsg = ''
      } catch (error) {
        console.log(error)
        this.errorMsg = 'Sorry, couldn\'t log in with a passkey'
      }
    },
    async registerKey() {
      if (!this.isValidLength || !this.hasValidChars) {
        // Validation criteria is already shown
        return
      }
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
        this.errorMsg = ''
      } catch (error) {
        console.log(error)
        this.errorMsg = 'Sorry, couldn\'t register a passkey'
      }
    },
    setView(view) {
      this.view = view
      this.username = ''
      this.loggedInUsername = ''
      this.errorMsg = ''
    },
    getValidationEmoji(isValid) {
      if (!this.username) {
        return ''
      }
      return isValid ? '✅' : '⚠️' 
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

.hello {
  max-width: 700px;
  margin: auto;
}
.register {
  margin: auto;
  max-width: 700px;
  margin-top: 20px;
}

.register p {
  text-align: justify;
}

.login {
  max-width: 700px;
  margin: auto;
  margin-top: 16px;
  margin-bottom: 20px;
}

.login p {
  text-align: justify;
}

.intro p {
  text-align: justify;
}

.demo-action {
  padding: 16px;
  width: 300px;
  margin: auto;
  border-radius: 8px;
  background-color: #dae0e6;
}

.demo-action p {
  text-align: center;
  margin-bottom: 0;
}
</style>
