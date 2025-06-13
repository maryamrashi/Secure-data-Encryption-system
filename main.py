import streamlit as st
from cryptography.fernet import Fernet
import hashlib

# Initialize session state
if "data_store" not in st.session_state:
    st.session_state.data_store = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "authorized" not in st.session_state:
    st.session_state.authorized = True

# Generate a fixed Fernet key (for demo purposes)
FERNET_KEY = Fernet.generate_key()
cipher_suite = Fernet(FERNET_KEY)

# Helper: Hash the passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# ---------- Streamlit UI ----------
st.set_page_config(page_title="🔐 Secure Encryption System")

st.title("🔐 Secure Data Encryption System")

# Force login if 3 failed attempts
if st.session_state.failed_attempts >= 3 or not st.session_state.authorized:
    st.session_state.authorized = False
    st.subheader("🔒 Login Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == "admin" and password == "admin123":  # Simple demo login
            st.success("✅ Re-authorized successfully.")
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
        else:
            st.error("❌ Invalid login.")
    st.stop()

# ---------- Menu ----------
menu = st.sidebar.radio("Navigation", ["🏠 Home", "➕ Store Data", "🔓 Retrieve Data"])

# ---------- Home ----------
if menu == "🏠 Home":
    st.info("Use the menu to store or retrieve encrypted data.")
    st.write("All data is stored in memory for this session only.")
    st.write("🔐 3 incorrect passkey attempts will require login.")

# ---------- Store Data ----------
elif menu == "➕ Store Data":
    st.subheader("➕ Store Encrypted Data")
    identifier = st.text_input("Unique ID (e.g., user1_data)")
    raw_text = st.text_area("Enter text to encrypt")
    passkey = st.text_input("Create a passkey", type="password")

    if st.button("Encrypt and Store"):
        if identifier and raw_text and passkey:
            encrypted_text = cipher_suite.encrypt(raw_text.encode()).decode()
            hashed_key = hash_passkey(passkey)
            st.session_state.data_store[identifier] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_key
            }
            st.success(f"✅ Data stored securely under ID: `{identifier}`")
        else:
            st.error("❗ Please fill in all fields.")

# ---------- Retrieve Data ----------
elif menu == "🔓 Retrieve Data":
    st.subheader("🔓 Retrieve Encrypted Data")
    identifier = st.text_input("Enter ID to retrieve")
    passkey = st.text_input("Enter your passkey", type="password")

    if st.button("Decrypt"):
        data = st.session_state.data_store.get(identifier)
        if data:
            if hash_passkey(passkey) == data["passkey"]:
                decrypted_text = cipher_suite.decrypt(data["encrypted_text"].encode()).decode()
                st.success("✅ Data decrypted successfully:")
                st.code(decrypted_text)
                st.session_state.failed_attempts = 0  # reset on success
            else:
                st.session_state.failed_attempts += 1
                st.error(f"❌ Incorrect passkey. Attempt {st.session_state.failed_attempts}/3")
        else:
            st.error("❗ No data found with that ID.")
