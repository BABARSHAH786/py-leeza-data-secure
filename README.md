data secure

✅ Summary of the Streamlit Secure Encryption App Code
This code creates a secure in-memory data encryption and retrieval system using Streamlit, Fernet encryption, and session state. It allows users to store data with a passkey and retrieve it securely.

🔍 Core Functionalities
1. Encryption & Storage
Users input plain text data and a passkey.

The data is encrypted using Fernet.

The passkey is hashed using SHA-256.

The encrypted data and hashed passkey are stored in memory (st.session_state.stored_data).

2. Decryption & Retrieval
Users provide the encrypted data and the passkey.

If the hashed passkey matches the stored one, the data is decrypted and shown.

If the passkey is wrong, it increases the failed_attempts count.

3. Security & Authentication
If the user fails to enter the correct passkey 3 times, they are marked as unauthorized.

Unauthorized users are redirected to a Login Page.

On the Login Page, entering the correct admin password (admin123) resets their status and allows access again.

4. Navigation
A sidebar menu lets users choose between:

Home: Welcome/info screen

Store Data: Encrypt and save user data

Retrieve Data: Enter encrypted text + passkey to decrypt

Login: For reauthorization after too many failed attempts

✅ Is This User-Friendly?
Yes, for a basic secure storage tool. It includes:

A clean UI with clear instructions.

Input validation and error feedback.

Session state to manage security context (memory only, no persistent storage).

A simple login system (demo-style).

🚀 How to Run This App
Step 1: Install Required Packages
Open your terminal and run:

bash
Copy
Edit
pip install streamlit cryptography
Step 2: Save the Code
Save the full code into a file named main.py.

Step 3: Run the App
If streamlit is not recognized, use the full path or add Python Scripts folder to your system PATH.

Try this (if PATH is set up):

bash
Copy
Edit
streamlit run main.py
If that doesn't work, try:

bash
Copy
Edit
python -m streamlit run main.py
Step 4: Use the Web App
Your browser will open to http://localhost:8501.

From there, you can:

Store data with a passkey.

Retrieve it by decrypting with the same passkey.

Be locked out after 3 failed attempts.

Re-login using admin123.

🧠 Suggested Improvements (Optional)
Add username/email fields to support multi-user use.

Save data to a file (e.g., JSON) for persistence.

Use PBKDF2 instead of SHA-256 for more secure hashing.

Add time-based lockouts after repeated failures.
