import streamlit as st
from hashlib import pbkdf2_hmac
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet
import json
import time
import os
import hashlib
import base64


DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

#== section Login Detail ==

if "authanticated_user" not in st.session_state:
    st.session_state.authanticated_user = None

if "failed_attempt" not in st.session_state:
    st.session_state.failed_attempt = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0
    

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data,f)

def generate_key(passkey):
    raw_key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(raw_key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(),SALT, 100000).hex()

# == cryptography fernet ===

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypt_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypt_text.encode()).decode()
    except:
        return None


stored_data = load_data()
    


st.title("Secure Data Encryption")

menu = ["Home", "Register", "Login", "Store Data", "Retrive Data",]
choice = st.sidebar.selectbox("Nevigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to *securely store and retrieve data* using unique passkeys.")

elif choice == "Register":
    st.subheader("Register New User")
    username = st.text_input("Choose User Name")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username in stored_data:
            st.warning("Already Registered")

        else:
            stored_data[username] = {
                "password": hash_password(password),
                "data":[]
            }
            save_data(stored_data)
            st.success("User Register Sucsessfully")
    else:
        st.error("Both Field are required")

# *** User Login ***
elif choice == "Login":
    st.subheader("User Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"To Many attempt Failed Please Wait {remaining} second")
        st.stop()
    username = st.text_input("username")
    password = st.text_input("password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authanticated_user = username
            st.session_state.failed_attempt = 0
            st.success(f"Welcome {username}")
        else:
            st.session_state.failed_attempt += 1
            remaining = 3 - st.session_state.failed_attempt
            st.error(f"Invalid Cradintials! Attempt Left:{remaining}")

            if st.session_state.failed_attempt >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("To Many failed attempts. Lockout for 60 seconds")
                st.stop()



# **** Store Data Securely ****
elif choice == "Store Data":
    if not st.session_state.authanticated_user:
        st.warning("Please Login First")
    else:
        st.subheader("📂 Store Data Securely")
        data = st.text_area("Enter Data to Encrypt")
        passkey = st.text_input("Enter Passkey", type="password")
    
        if st.button("Encrypt & Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authanticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("Stored Data Successfully")

            else:
                st.error("All field are Required")
                

elif choice == "Retrive Data":
    if not st.session_state.authanticated_user:
        st.warning("Please Login First")

    else:
        st.subheader("Retrive Data")
        user_data = stored_data.get(st.session_state.authanticated_user, {}).get("data", [])

        if not user_data:
            st.info("NO Data Found")
        else:
            st.write("Encrypted Data Enteries")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

            encrypted_input = st.text_area("Enter Encrypted Text:")
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"Decrypted : {result}")
                else:
                    st.error("Incorrect Passkey or Corrupted Data")


