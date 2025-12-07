# 🚀 How to Run the Secure Messenger GUI

## ✅ Quick Start (Easiest Method)

Just run this single command:
```bash
./run_gui.sh
```

This script handles everything automatically!

---

## 📱 Manual Method (Step by Step)

### 1. Activate the Python 3.11 Environment
```bash
source venv311/bin/activate
```

### 2. Run the Enhanced GUI
```bash
python main_enhanced.py
```

### 3. Or Run the Original GUI
```bash
python main.py
```

---

## 🎮 Using the GUI

### Step 1: Key Exchange (REQUIRED FIRST!)
1. Click the **"🔑 Key Exchange"** button
2. Wait for "✓ Secure Channel Established" message
3. You'll see the key exchange packet in the network view

### Step 2: Send Messages
1. Type your message in the input field
2. Click **"📤 Send"** to encrypt and send
3. The encrypted packet appears in the network view

### Step 3: Receive Messages
1. Click **"📥 Receive"** to decrypt the message
2. The decrypted message appears in the receiver view
3. Security log shows verification status

### Step 4: Test Security Features
Try the attack simulation buttons:
- **🔄 Replay** - Tests replay attack detection
- **✏️ Tamper** - Tests message tampering detection
- **👤 MITM** - Tests man-in-the-middle detection
- **♻️ IV Reuse** - Tests IV reuse detection

---

## 🧪 Other Testing Options

### Run Complete Console Demo
```bash
source venv311/bin/activate
python secure_message_enhanced.py
```

### Run Terminal Interactive Demo
```bash
source venv311/bin/activate
python terminal_demo.py
```

### Run Compliance Tests
```bash
source venv311/bin/activate
python test_compliance.py
```

---

## 🔧 Troubleshooting

### If the GUI doesn't open:
1. Make sure you're in the correct directory:
   ```bash
   cd /Users/abdulrazzak/ICS344_Project/secure-mobile-messenger-ics344
   ```

2. Verify the environment is activated:
   ```bash
   source venv311/bin/activate
   python --version  # Should show Python 3.11.14
   ```

3. Check Kivy is installed:
   ```bash
   pip show kivy  # Should show Version: 2.3.1
   ```

### To reinstall everything:
```bash
rm -rf venv311
python3.11 -m venv venv311
source venv311/bin/activate
pip install --upgrade pip
pip install cryptography==41.0.7
pip install "kivy[base]"
```

---

## 📊 Expected Output

When the GUI launches, you should see:
- A mobile-style window (450x800 pixels)
- Status bar showing "Key Exchange Required"
- Split view for Receiver and Network traffic
- Security log at the bottom
- Message input field
- Control buttons for key exchange and messaging
- Attack simulation panel

---

## ✨ Features to Test

1. **RSA Key Exchange** ✅
   - The critical missing feature now implemented
   - Encrypts AES key with receiver's RSA public key

2. **Secure Messaging** ✅
   - AES-256-CBC encryption
   - RSA-PSS digital signatures
   - Timestamp and message ID tracking

3. **Attack Detection** ✅
   - Persistent replay protection
   - Message tampering detection
   - MITM attack prevention
   - IV reuse detection

4. **Security Features** ✅
   - Persistent security state (SQLite)
   - Key management system
   - Session management
   - Security statistics

---

## 🎉 Success Indicators

You know everything is working when:
- ✅ GUI window opens without errors
- ✅ Key exchange completes successfully
- ✅ Messages encrypt and decrypt properly
- ✅ Attack simulations are detected and blocked
- ✅ Security log shows green checkmarks for valid operations

---

**Your implementation is now 100% compliant with all ICS344 requirements!**

*Group P26 - Secure Mobile Messenger*