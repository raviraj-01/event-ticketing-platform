import { initializeApp } from "https://www.gstatic.com/firebasejs/10.14.1/firebase-app.js";
import {
  getAuth,
  GoogleAuthProvider,
  browserLocalPersistence,
  setPersistence,
  signInWithPopup,
  signInWithRedirect,
  getRedirectResult,
  signOut,
} from "https://www.gstatic.com/firebasejs/10.14.1/firebase-auth.js";

const firebaseConfig = {
  apiKey: "AIzaSyCmHaayfQy0WSOE1HG_bDjs4tiVJFDFb84",
  authDomain: "vybera.firebaseapp.com",
  projectId: "vybera",
  storageBucket: "vybera.firebasestorage.app",
  messagingSenderId: "544899681732",
  appId: "1:544899681732:web:72950958f1ac6b83356891",
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
setPersistence(auth, browserLocalPersistence).catch((err) => {
  console.error("Google auth persistence setup failed:", err);
});
const googleProvider = new GoogleAuthProvider();
googleProvider.setCustomParameters({
  prompt: "select_account",
});

function isCordovaWebView() {
  const ua = navigator.userAgent || "";
  return !!window.cordova || window.location.protocol === "file:" || /\bwv\)/i.test(ua) || /; wv\)/i.test(ua);
}

function normalizeLocalAuthOrigin() {
  const isFilePreview = window.location.protocol === "file:";
  const isLoopbackIp = ["127.0.0.1", "0.0.0.0"].includes(window.location.hostname);
  if (!isFilePreview && !isLoopbackIp) return false;

  const port = window.VYBERA_DEV_PORT || "3003";
  const path = isFilePreview
    ? "/"
    : window.location.pathname;
  window.location.href = `http://localhost:${port}${path}${window.location.search}${window.location.hash}`;
  return true;
}

window.vyberaFirebaseGoogleReady = true;
let googleSessionApplied = false;
let googleRedirectResultPromise = Promise.resolve(false);

function markGooglePending() {
  try { window.sessionStorage.setItem("VYBERA_GOOGLE_PENDING", "1"); } catch (_) {}
}

function clearGooglePending() {
  try { window.sessionStorage.removeItem("VYBERA_GOOGLE_PENDING"); } catch (_) {}
}

function forceBuyerHome() {
  if (typeof window.showPage === "function") {
    const homeNav = document.querySelector(".buyer-nav .nav-btn");
    window.showPage("page-home", homeNav);
  } else {
    window.location.hash = "page-home";
  }
}

function waitForAppLogin() {
  if (typeof window.applySocialLogin === "function") {
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer = null;
    let poller = null;
    const cleanup = () => {
      window.removeEventListener("vybera-app-auth-ready", finish);
      clearTimeout(timer);
      clearInterval(poller);
    };
    const finish = () => {
      if (settled || typeof window.applySocialLogin !== "function") return;
      settled = true;
      cleanup();
      resolve();
    };
    timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new Error("App login is still loading. Please try again."));
    }, 6000);
    poller = setInterval(finish, 50);
    window.addEventListener("vybera-app-auth-ready", finish, { once: true });
    finish();
  });
}

// The server only accepts a Google-signed ID token (POST /auth/google verifies
// signature, audience and email). Never send a bare name/email: that was the
// unverified /social-login route (C3), now deleted.
function googleIdTokenFromResult(result) {
  const credential = result ? GoogleAuthProvider.credentialFromResult(result) : null;
  return (credential && credential.idToken) || "";
}

async function finishGoogleUser(googleIdToken) {
  if (googleSessionApplied) return;
  if (!googleIdToken) {
    throw new Error("Google sign-in did not return a verifiable token. Please try again.");
  }
  await waitForAppLogin();
  await window.applySocialLogin({ credential: googleIdToken }, { force: true });
  googleSessionApplied = true;
  clearGooglePending();
  setTimeout(forceBuyerHome, 80);
}

async function getGoogleWebClientId() {
  const base = String(window.VYBERA_API_BASE || "").replace(/\/$/, "");
  const resp = await fetch(`${base}/auth/google/client-config`);
  const data = await resp.json().catch(() => ({}));
  return String((data && data.clientId) || "").trim();
}

if (!isCordovaWebView()) {
  googleRedirectResultPromise = getRedirectResult(auth)
    .then((result) => {
      if (result && result.user) {
        return finishGoogleUser(googleIdTokenFromResult(result)).then(() => true);
      }
      return false;
    })
    .catch((err) => {
      console.error("Google redirect result failed:", err);
      return false;
    });
}

window.vyberaFirebaseCompleteGoogleReturn = async function vyberaFirebaseCompleteGoogleReturn() {
  if (isCordovaWebView()) return false;
  if (normalizeLocalAuthOrigin()) return true;

  markGooglePending();
  const redirectHandled = await googleRedirectResultPromise;
  if (redirectHandled || googleSessionApplied) return true;

  // A cached Firebase session has no fresh Google ID token to verify, so always
  // go through Google again instead of trusting the cached profile.
  return signInWithRedirect(auth, googleProvider);
};

window.vyberaFirebaseGoogleSignIn = async function vyberaFirebaseGoogleSignIn() {
  try {
    if (isCordovaWebView()) {
      markGooglePending();

      // cordova-plugin-googleplus returns a Google ID token for the web client ID;
      // the server verifies it. The client ID comes from the server config.
      if (window.plugins && window.plugins.googleplus) {
        const webClientId = await getGoogleWebClientId();
        if (!webClientId) {
          clearGooglePending();
          alert("Google sign-in is not configured on the server.");
          return;
        }
        window.plugins.googleplus.login(
          { webClientId, offline: false },
          async (userData) => {
            try {
              await finishGoogleUser(userData && userData.idToken);
            } catch (err) {
              console.error("Google sign-in failed:", err);
              clearGooglePending();
              alert("Google sign-in failed: " + (err.message || "Unknown error"));
            }
          },
          (err) => {
            console.error("Google login failed:", err);
            clearGooglePending();
            alert("Google sign-in failed: " + ((err && err.message) || "Please try again"));
          }
        );
        return;
      }

      alert("Google sign-in needs the Google Sign-In plugin in this app build.");
      clearGooglePending();
      return;
    }
    if (normalizeLocalAuthOrigin()) return;
    markGooglePending();
    const isLocalHost = ["localhost", "127.0.0.1"].includes(window.location.hostname);
    const isAppReturnFlow = new URLSearchParams(window.location.search).get("google") === "1";
    if (isAppReturnFlow && !isLocalHost) {
      return window.vyberaFirebaseCompleteGoogleReturn();
    }
    if ((window.VYBERA_GOOGLE_USE_REDIRECT === true || isAppReturnFlow) && !isLocalHost && !isCordovaWebView()) {
      return signInWithRedirect(auth, googleProvider);
    }
    const result = await signInWithPopup(auth, googleProvider);
    return finishGoogleUser(googleIdTokenFromResult(result));
  } catch (err) {
    console.error("Google sign-in failed:", err);

    if (err.code === "auth/popup-closed-by-user" || err.code === "auth/cancelled-popup-request") {
      clearGooglePending();
      return;
    }

    if (
      err.code === "auth/popup-blocked" ||
      err.code === "auth/operation-not-supported-in-this-environment" ||
      err.code === "auth/internal-error"
    ) {
      if (!isCordovaWebView()) {
        markGooglePending();
        return signInWithRedirect(auth, googleProvider);
      }
    }

    if (err.code === "auth/unauthorized-domain") {
      alert(
        `Google login is blocked for "${window.location.hostname}". ` +
        "Add this exact hostname in Firebase Console > Authentication > Settings > Authorized domains. " +
        "For localhost testing, add localhost and 127.0.0.1."
      );
      clearGooglePending();
      return;
    }

    if (!isCordovaWebView()) {
      alert(err.message || "Google sign-in failed. Please try again.");
    }
    clearGooglePending();
  }
};

if (!isCordovaWebView()) {
  window.signInWithGoogle = window.vyberaFirebaseGoogleSignIn;
}

window.vyberaFirebaseSignOut = function() {
  return signOut(auth).catch((err) => {
    console.error("Firebase signOut failed:", err);
  });
};
