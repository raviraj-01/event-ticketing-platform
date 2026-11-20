import { initializeApp } from "https://www.gstatic.com/firebasejs/10.14.1/firebase-app.js";
import {
  getAuth,
  GoogleAuthProvider,
  signInWithCredential,
  browserLocalPersistence,
  setPersistence,
  signInWithPopup,
  signInWithRedirect,
  getRedirectResult,
  onAuthStateChanged,
  signOut,
} from "https://www.gstatic.com/firebasejs/10.14.1/firebase-auth.js";

const firebaseConfig = {
  apiKey: "AIzaSyCmHaayfQy0WSOE1HG_bDjs4tiVJFDFb84",
  authDomain: "vybera.firebaseapp.com",
  projectId: "vybera",
  storageBucket: "vybera.firebasestorage.app",
  messagingSenderId: "544899681732",
  appId: "1:544899681732:web:72950958f1ac6b83356891",
  oauthClientId: "544899681732-68u9ma1sfqtttsfp2nde8q6jtff9bh6g.apps.googleusercontent.com",
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

function hasGooglePending() {
  try { return window.sessionStorage.getItem("VYBERA_GOOGLE_PENDING") === "1"; } catch (_) { return false; }
}

function forceBuyerHome() {
  if (typeof window.showPage === "function") {
    const homeNav = document.querySelector(".buyer-nav .nav-btn");
    window.showPage("page-home", homeNav);
  } else {
    window.location.hash = "page-home";
  }
}

function waitForInitialAuthUser() {
  return new Promise((resolve) => {
    const unsubscribe = onAuthStateChanged(auth, (user) => {
      unsubscribe();
      resolve(user || null);
    }, () => {
      unsubscribe();
      resolve(null);
    });
  });
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

async function finishGoogleUser(user) {
  if (!user || googleSessionApplied) return;
  const displayName = user.displayName || "Google User";
  const email = user.email || "";
  if (!email) {
    throw new Error("Google account did not return an email address.");
  }
  await waitForAppLogin();
  await window.applySocialLogin({
    name: displayName,
    email,
    photoURL: user.photoURL || "",
  }, { force: true });
  googleSessionApplied = true;
  clearGooglePending();
  setTimeout(forceBuyerHome, 80);
}

if (!isCordovaWebView()) {
  googleRedirectResultPromise = getRedirectResult(auth)
    .then((result) => {
      if (result && result.user) {
        return finishGoogleUser(result.user).then(() => true);
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

  const existingUser = auth.currentUser || await waitForInitialAuthUser();
  if (existingUser) {
    await finishGoogleUser(existingUser);
    return true;
  }

  return signInWithRedirect(auth, googleProvider);
};

window.vyberaFirebaseGoogleSignIn = async function vyberaFirebaseGoogleSignIn() {
  try {
    if (isCordovaWebView()) {
      markGooglePending();
      
      // Use cordova-plugin-googleplus for direct Google Sign-In
      if (window.plugins && window.plugins.googleplus) {
        window.plugins.googleplus.login(
          {
            webClientId: '544899681732-68u9ma1sfqtttsfp2nde8q6jtff9bh6g.apps.googleusercontent.com',
            offline: true
          },
          async (userData) => {
            try {
              const credential = GoogleAuthProvider.credential(userData.idToken);
              const userCredential = await signInWithCredential(auth, credential);
              await finishGoogleUser(userCredential.user);
            } catch (err) {
              console.error('Firebase credential sign-in failed:', err);
              clearGooglePending();
              alert('Google sign-in failed: ' + (err.message || 'Unknown error'));
            }
          },
          (err) => {
            console.error('Google login failed:', err);
            clearGooglePending();
            alert('Google sign-in failed: ' + (err.message || 'Please try again'));
          }
        );
        return;
      }
      
      if (typeof window.openGoogleInSystemBrowser === "function") {
        return window.openGoogleInSystemBrowser();
      }
      alert("Google login is loading. Please try again in a moment.");
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
    return finishGoogleUser(result.user);
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

// Always assign for Cordova WebView
window.signInWithGoogle = window.vyberaFirebaseGoogleSignIn;

window.vyberaFirebaseSignOut = function() {
  return signOut(auth).catch((err) => {
    console.error("Firebase signOut failed:", err);
  });
};
