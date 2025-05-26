import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Key and cipher setup (constant for this demo)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Session state setup
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # {"encrypted_text": {"encrypted_text": ..., "passkey": ...}}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = True  # Controls redirect after 3 failed attempts

# Helper: hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt text
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt text with passkey check
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    data = st.session_state.stored_data.get(encrypted_text)

    if data and data["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

# UI
st.title("🔒 Secure Data Encryption System")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home
if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.write("Securely **store and retrieve data** using encryption and passkeys.")

# Store Data
elif choice == "Store Data":
    st.subheader("📥 Store Data Securely")
    user_data = st.text_area("Enter data:")
    passkey = st.text_input("Enter passkey:", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed_pass = hash_passkey(passkey)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_pass,
            }
            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ Please enter both data and passkey.")

# Retrieve Data
elif choice == "Retrieve Data":
    if not st.session_state.authorized:
        st.warning("🔒 Unauthorized access. Please reauthorize.")
        st.switch_page("Login")

    st.subheader("🔐 Retrieve Your Data")
    encrypted_input = st.text_area("Enter Encrypted Data:")
    passkey_input = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey_input:
            result = decrypt_data(encrypted_input, passkey_input)
            if result:
                st.success("✅ Decrypted Data:")
                st.code(result, language="text")
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey. Attempts left: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.authorized = False
                    st.warning("🚫 Too many failed attempts. Redirecting to login...")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Please enter both encrypted data and passkey.")

# Login Page
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_input = st.text_input("Enter Admin Password:", type="password")
    if st.button("Login"):
        if login_input == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Reauthorized successfully.")
        else:
            st.error("❌ Incorrect password.")
