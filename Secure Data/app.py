import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# ----------------------------
# Setup and Configurations
# ----------------------------
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  # Format: {"label": {"encrypted_text": ..., "passkey": ...}}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'reauthorized' not in st.session_state:
    st.session_state.reauthorized = False

# Generate a consistent key (should be stored securely in production)
@st.cache_resource
def generate_key():
    return Fernet.generate_key()

cipher = Fernet(generate_key())

# ----------------------------
# Helper Functions
# ----------------------------
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# ----------------------------
# Streamlit UI
# ----------------------------
st.title("🛡️ Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# ----------------------------
# Home Page
# ----------------------------
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Store and retrieve data securely using passkeys.")

# ----------------------------
# Store Data
# ----------------------------
elif choice == "Store Data":
    st.subheader("📦 Store Data Securely")

    label = st.text_input("Enter Unique Label (e.g., user1_data):")
    data = st.text_area("Enter Your Data:")
    passkey = st.text_input("Set a Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if label and data and passkey:
            if label in st.session_state.stored_data:
                st.error("❌ This label already exists. Choose a unique one.")
            else:
                encrypted_text = encrypt_data(data)
                hashed_passkey = hash_passkey(passkey)
                st.session_state.stored_data[label] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                }
                st.success("✅ Data encrypted and stored successfully!")
        else:
            st.warning("⚠️ Please fill all fields.")

# ----------------------------
# Retrieve Data
# ----------------------------
elif choice == "Retrieve Data":
    if st.session_state.failed_attempts >= 3 and not st.session_state.reauthorized:
        st.warning("🔒 Too many failed attempts. Please login again.")
        st.switch_page("Login")

    st.subheader("🔓 Retrieve Data")

    label = st.text_input("Enter Data Label:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if label and passkey:
            if label in st.session_state.stored_data:
                hashed_input = hash_passkey(passkey)
                record = st.session_state.stored_data[label]

                if hashed_input == record["passkey"]:
                    decrypted = decrypt_data(record["encrypted_text"])
                    st.success(f"✅ Decrypted Data: {decrypted}")
                    st.session_state.failed_attempts = 0  # Reset on success
                else:
                    st.session_state.failed_attempts += 1
                    attempts_left = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")

                    if st.session_state.failed_attempts >= 3:
                        st.warning("🚫 Too many failed attempts. Redirecting to Login.")
                        st.experimental_rerun()
            else:
                st.error("❌ No data found for the given label.")
        else:
            st.warning("⚠️ All fields are required.")

# ----------------------------
# Login Page
# ----------------------------
elif choice == "Login":
    st.subheader("🔐 Reauthorize Access")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Demo password
            st.success("✅ Reauthorized successfully.")
            st.session_state.failed_attempts = 0
            st.session_state.reauthorized = True
            st.switch_page("Retrieve Data")
        else:
            st.error("❌ Incorrect password.")
