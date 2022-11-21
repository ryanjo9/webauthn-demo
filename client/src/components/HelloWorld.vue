<template>
  <div class="hello">
    <button type="button" class="btn btn-success" @click="registerKey">Register</button>

    <button type="button" class="btn btn-success" @click="registerKey">Login</button>
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
      username: 'vuetest'
    }
  },
  methods: {
    async validateKey() {
      try {
        const { data: options } = await axios.post('/api/generate-challenge', {purpose: 'authentication'})
      
        options.challenge = decode(options.challenge)

        let key = await navigator.credentials.create({ publicKey: options })

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
      } catch (error) {
        console.log(error)
      }
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
</style>
