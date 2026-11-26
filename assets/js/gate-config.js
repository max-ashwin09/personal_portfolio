/**
 * VCRYPT Portfolio Access Gate Configuration
 *
 * Local Mode:
 * - Automatically active when served via `node server.mjs` (detects `/api/gate/mode`).
 *
 * Live Cloud Mode (GitHub Pages / Netlify / Firebase Hosting):
 * - Create a free Firebase project, enable Anonymous Auth + Google (or Email/Password) Auth
 *   and Firestore, deploy `firestore.rules`, store your AES vault key in Firestore document
 *   `vault_secrets/portfolio_key` as `{ keyBase64: "..." }`, and paste your web config below.
 */
window.VCRYPT_GATE_CONFIG = {
  // Email authorized in firestore.rules to open admin.html and approve/reject visitors
  adminEmail: 'mr.vivek7009@gmail.com',

  // Local Node server API prefix
  localApiBase: '/api',

  // Optional: Web3Forms public access key to get instant email alerts on new requests
  web3formsAccessKey: '',

  // Fill these values when deploying to static hosting (GitHub Pages, etc.)
  firebaseConfig: {
    apiKey: '',
    authDomain: '',
    projectId: '',
    storageBucket: '',
    messagingSenderId: '',
    appId: '',
  },
};
